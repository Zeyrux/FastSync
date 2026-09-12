cmake_minimum_required(VERSION 3.22)

project(FastFileTransfer VERSION 2.19.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -g -O3)

# --- Sanitizer option ---
set(SANITIZER "none" CACHE STRING "Sanitizer to enable (address, thread, undefined, none)")
set_property(CACHE SANITIZER PROPERTY STRINGS address thread undefined none)

if(SANITIZER STREQUAL "address")
	add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g)
	add_link_options(-fsanitize=address)
elseif(SANITIZER STREQUAL "thread")
	add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -g)
	add_link_options(-fsanitize=thread)
elseif(SANITIZER STREQUAL "undefined")
	add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer -g)
	add_link_options(-fsanitize=undefined)
elseif(NOT SANITIZER STREQUAL "none")
	message(FATAL_ERROR "Unknown sanitizer: ${SANITIZER}. Supported values: address, thread, undefined, none")
endif()

# --- Strict warnings option ---
option(STRICT_WARNINGS "Enable strict warnings (Wextra, Wpedantic, Werror)" OFF)
if(STRICT_WARNINGS)
	add_compile_options(-Wextra -Wpedantic -Werror)
endif()

# --- Coverage option ---
option(ENABLE_COVERAGE "Enable gcov coverage" OFF)
if(ENABLE_COVERAGE)
	add_compile_options(--coverage -fprofile-arcs -ftest-coverage -O0 -g)
	add_link_options(--coverage)
endif()

# --- Build hardening option ---
# Production hardening is applied to the shipping server/client binaries only,
# and only when no sanitizer or coverage instrumentation is active: sanitizers
# carry their own instrumentation, and _FORTIFY_SOURCE requires an optimising
# build (never the -O0 used for coverage).
option(ENABLE_HARDENING "Enable compiler/linker hardening for production targets" ON)
set(HARDENING_ACTIVE OFF)
if(ENABLE_HARDENING AND SANITIZER STREQUAL "none" AND NOT ENABLE_COVERAGE)
	set(HARDENING_ACTIVE ON)
endif()

include(FetchContent)
FetchContent_Declare(
  xxhash
  GIT_REPOSITORY https://github.com/Cyan4973/xxHash
  # v0.8.3 is a lightweight tag pointing at this exact commit (no ^{} peel
  # entry); pin the commit SHA instead of the mutable tag.
  GIT_TAG e626a72bc2321cd320e953a0ccf1584cad60f363 # v0.8.3
  SOURCE_SUBDIR cmake_unofficial
)
FetchContent_MakeAvailable(xxhash)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

find_library(ZSTD_LIBRARY zstd)
if(NOT ZSTD_LIBRARY)
	message(FATAL_ERROR "zstd library not found. Ensure it is in your nix-shell!")
endif()

find_package(OpenSSL REQUIRED)

file(GLOB SHARED_SRCS "src/shared/*.c")
set(FILE_STORE_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/src/shared/file_store.c")
list(REMOVE_ITEM SHARED_SRCS ${FILE_STORE_SRCS})
file(GLOB SERVER_SRCS "src/server/*.c")
set(SERVER_RECEIVER_SRCS src/server/receiver.c)
file(GLOB CLIENT_SRCS "src/client/*.c")

# --- Main executables ---
add_executable(server ${SERVER_SRCS} ${SHARED_SRCS} ${FILE_STORE_SRCS})
target_include_directories(server PRIVATE src/shared src/server src/client)
target_link_libraries(server PRIVATE Threads::Threads ${ZSTD_LIBRARY} OpenSSL::SSL OpenSSL::Crypto xxhash)

add_executable(client ${CLIENT_SRCS} ${SHARED_SRCS} ${FILE_STORE_SRCS} ${SERVER_RECEIVER_SRCS})
target_include_directories(client PRIVATE src/shared src/server src/client)
target_link_libraries(client PRIVATE Threads::Threads ${ZSTD_LIBRARY} OpenSSL::SSL OpenSSL::Crypto xxhash)

# --- Production hardening ---
# Each compile flag is probed so a compiler/architecture that lacks it still
# configures cleanly.  _FORTIFY_SOURCE is guarded separately because it only
# works in an optimising build.  xxHash is a static archive built by
# FetchContent, so it must be position-independent for the -pie link.
if(HARDENING_ACTIVE)
	set_target_properties(xxhash PROPERTIES POSITION_INDEPENDENT_CODE ON)
	include(CheckCCompilerFlag)
	foreach(flag -fstack-protector-strong -fstack-clash-protection -fPIE)
		string(MAKE_C_IDENTIFIER "HARDEN_${flag}" _harden_var)
		check_c_compiler_flag("${flag}" ${_harden_var})
	endforeach()
	check_c_compiler_flag("-D_FORTIFY_SOURCE=2" HARDEN_FORTIFY_SOURCE)
	foreach(target server client)
		foreach(flag -fstack-protector-strong -fstack-clash-protection -fPIE)
			string(MAKE_C_IDENTIFIER "HARDEN_${flag}" _harden_var)
			if(${_harden_var})
				target_compile_options(${target} PRIVATE ${flag})
			endif()
		endforeach()
		if(HARDEN_FORTIFY_SOURCE)
			target_compile_options(${target} PRIVATE -D_FORTIFY_SOURCE=2)
		endif()
		target_link_options(${target} PRIVATE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
	endforeach()
endif()

# --- Testing ---
enable_testing()

# Common test libraries
set(TEST_LIBS Threads::Threads ${ZSTD_LIBRARY} OpenSSL::SSL OpenSSL::Crypto xxhash)
set(TEST_INCLUDES tests src/shared src/server src/client)

# Monolithic test binary (backward compatible)
file(GLOB TEST_SRCS "tests/test_*.c" "tests/runner.c")
add_executable(tests ${TEST_SRCS} ${SHARED_SRCS} ${FILE_STORE_SRCS} ${SERVER_RECEIVER_SRCS} src/client/scanner.c src/client/change_list.c src/client/client_cli.c src/client/client_validation.c src/client/usage.c src/server/server_cli.c)
target_include_directories(tests PRIVATE ${TEST_INCLUDES})
target_compile_definitions(tests PRIVATE FASTSYNC_TEST_BUILD)
target_link_libraries(tests PRIVATE ${TEST_LIBS})
add_test(NAME unit_all COMMAND tests)

# --- Fuzz targets (requires clang) ---
option(ENABLE_FUZZ "Build fuzz targets (requires clang)" OFF)
if(ENABLE_FUZZ)
  if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "ENABLE_FUZZ requires Clang (compiler is ${CMAKE_C_COMPILER_ID})")
  endif()
  file(GLOB FUZZ_SRCS "tests/fuzz/*.c")
	foreach(FUZZ_SRC ${FUZZ_SRCS})
		get_filename_component(FUZZ_NAME ${FUZZ_SRC} NAME_WE)
    add_executable(${FUZZ_NAME} ${FUZZ_SRC} ${SHARED_SRCS} ${FILE_STORE_SRCS} ${SERVER_RECEIVER_SRCS})
		target_include_directories(${FUZZ_NAME} PRIVATE ${TEST_INCLUDES})
		target_compile_options(${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
		target_link_options(${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address,undefined)
		target_link_libraries(${FUZZ_NAME} PRIVATE ${TEST_LIBS})
	endforeach()
endif()
