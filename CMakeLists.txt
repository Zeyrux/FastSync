cmake_minimum_required(VERSION 3.22)

project(FastFileTransfer)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -g -O3)

# --- Sanitizer option ---
set(SANITIZER "none" CACHE STRING "Sanitizer to enable (address, thread, none)")
set_property(CACHE SANITIZER PROPERTY STRINGS address thread none)

if(SANITIZER STREQUAL "address")
	add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g)
	add_link_options(-fsanitize=address)
elseif(SANITIZER STREQUAL "thread")
	add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -g)
	add_link_options(-fsanitize=thread)
elseif(NOT SANITIZER STREQUAL "none")
	message(FATAL_ERROR "Unknown sanitizer: ${SANITIZER}. Supported values: address, thread, none")
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

include(FetchContent)
FetchContent_Declare(
  xxhash
  GIT_REPOSITORY https://github.com/Cyan4973/xxHash
  GIT_TAG v0.8.3
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
file(GLOB SERVER_SRCS "src/server/*.c")
file(GLOB CLIENT_SRCS "src/client/*.c")

# --- Main executables ---
add_executable(server ${SERVER_SRCS} ${SHARED_SRCS})
target_include_directories(server PRIVATE src/shared src/server src/client)
target_link_libraries(server PRIVATE Threads::Threads ${ZSTD_LIBRARY} OpenSSL::SSL OpenSSL::Crypto xxhash)

add_executable(client ${CLIENT_SRCS} ${SHARED_SRCS})
target_include_directories(client PRIVATE src/shared src/server src/client)
target_link_libraries(client PRIVATE Threads::Threads ${ZSTD_LIBRARY} OpenSSL::SSL OpenSSL::Crypto xxhash)

# --- Testing ---
enable_testing()

# Common test libraries
set(TEST_LIBS Threads::Threads ${ZSTD_LIBRARY} OpenSSL::SSL OpenSSL::Crypto xxhash)
set(TEST_INCLUDES tests src/shared src/server src/client)

# Monolithic test binary (backward compatible)
file(GLOB TEST_SRCS "tests/test_*.c" "tests/runner.c")
add_executable(tests ${TEST_SRCS} ${SHARED_SRCS} src/client/scanner.c)
target_include_directories(tests PRIVATE ${TEST_INCLUDES})
target_link_libraries(tests PRIVATE ${TEST_LIBS})
add_test(NAME unit_all COMMAND tests)

# --- Fuzz targets (requires clang) ---
option(ENABLE_FUZZ "Build fuzz targets (requires clang)" OFF)
if(ENABLE_FUZZ)
	file(GLOB FUZZ_SRCS "tests/fuzz/*.c")
	foreach(FUZZ_SRC ${FUZZ_SRCS})
		get_filename_component(FUZZ_NAME ${FUZZ_SRC} NAME_WE)
		add_executable(${FUZZ_NAME} ${FUZZ_SRC} ${SHARED_SRCS})
		target_include_directories(${FUZZ_NAME} PRIVATE ${TEST_INCLUDES})
		target_compile_options(${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
		target_link_options(${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address,undefined)
		target_link_libraries(${FUZZ_NAME} PRIVATE ${TEST_LIBS})
	endforeach()
endif()
