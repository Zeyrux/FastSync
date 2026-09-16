cmake_minimum_required(VERSION 3.22)

project(FastFileTransfer VERSION 2.23.0)

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

# --- Explicit source lists ---
# The shared library is self-contained: it must never depend on the client or
# server modules.  In particular, the receiver pipeline (receive_thread /
# write_thread) lives under src/server, not here, so the client executable can
# link the shared library without pulling in any server code.
set(SHARED_SRCS
	src/shared/array_list.c
	src/shared/batch.c
	src/shared/charset.c
	src/shared/checksum.c
	src/shared/chmod.c
	src/shared/chunk.c
	src/shared/compression.c
	src/shared/config.c
	src/shared/credentials.c
	src/shared/daemon_conf.c
	src/shared/daemon_limits.c
	src/shared/data.c
	src/shared/delay_updates.c
	src/shared/delete_plan.c
	src/shared/delta.c
	src/shared/file.c
	src/shared/file_list.c
	src/shared/file_receive.c
	src/shared/file_send.c
	src/shared/file_store.c
	src/shared/filter.c
	src/shared/format.c
	src/shared/hardlink.c
	src/shared/identity.c
	src/shared/log.c
	src/shared/metadata.c
	src/shared/motd.c
	src/shared/multiprocessing.c
	src/shared/protocol.c
	src/shared/queue.c
	src/shared/stop_condition.c
	src/shared/transport_ssh.c
	src/shared/transport_tcp.c
	src/shared/transport_tls.c
	src/shared/utils.c
	src/shared/xattr.c
)

# Server implementation (no main): the receiver read/write pipeline plus the
# CLI parser.  The server executable adds its own main (server.c).
set(SERVER_CORE_SRCS
	src/server/receiver.c
	src/server/receiver_pipeline.c
	src/server/server_cli.c
)
set(SERVER_MAIN_SRCS src/server/server.c)

# Client implementation (no main): everything except the CLI entry point.
set(CLIENT_CORE_SRCS
	src/client/change_list.c
	src/client/client_send.c
	src/client/client_validation.c
	src/client/scanner.c
	src/client/usage.c
)
set(CLIENT_MAIN_SRCS src/client/client_cli.c)

# --- Library targets ---
add_library(fastsync_shared STATIC ${SHARED_SRCS})
target_include_directories(fastsync_shared PUBLIC src/shared)
target_link_libraries(fastsync_shared PUBLIC Threads::Threads ${ZSTD_LIBRARY} OpenSSL::SSL
											OpenSSL::Crypto xxhash)

add_library(fastsync_client_core STATIC ${CLIENT_CORE_SRCS})
target_include_directories(fastsync_client_core PUBLIC src/client)
target_link_libraries(fastsync_client_core PUBLIC fastsync_shared)

add_library(fastsync_server_core STATIC ${SERVER_CORE_SRCS})
target_include_directories(fastsync_server_core PUBLIC src/server)
target_link_libraries(fastsync_server_core PUBLIC fastsync_shared)

# --- Main executables ---
# The client links only the shared library and its own core; it deliberately
# does NOT get src/server on its include path nor compile receiver.c.
add_executable(server ${SERVER_MAIN_SRCS})
target_link_libraries(server PRIVATE fastsync_server_core)

add_executable(client ${CLIENT_MAIN_SRCS})
target_link_libraries(client PRIVATE fastsync_client_core)

# --- Production hardening ---
# Each compile flag is probed so a compiler/architecture that lacks it still
# configures cleanly.  _FORTIFY_SOURCE is guarded separately because it only
# works in an optimising build.  xxHash is a static archive built by
# FetchContent, so it must be position-independent for the -pie link; the same
# applies to the first-party static libraries linked into the -pie binaries.
if(HARDENING_ACTIVE)
	set_target_properties(xxhash fastsync_shared fastsync_server_core fastsync_client_core
						  PROPERTIES POSITION_INDEPENDENT_CODE ON)
	include(CheckCCompilerFlag)
	foreach(flag -fstack-protector-strong -fstack-clash-protection -fPIE)
		string(MAKE_C_IDENTIFIER "HARDEN_${flag}" _harden_var)
		check_c_compiler_flag("${flag}" ${_harden_var})
	endforeach()
	check_c_compiler_flag("-D_FORTIFY_SOURCE=2" HARDEN_FORTIFY_SOURCE)
	foreach(target fastsync_shared fastsync_server_core fastsync_client_core server client)
		foreach(flag -fstack-protector-strong -fstack-clash-protection -fPIE)
			string(MAKE_C_IDENTIFIER "HARDEN_${flag}" _harden_var)
			if(${_harden_var})
				target_compile_options(${target} PRIVATE ${flag})
			endif()
		endforeach()
		if(HARDEN_FORTIFY_SOURCE)
			target_compile_options(${target} PRIVATE -D_FORTIFY_SOURCE=2)
		endif()
	endforeach()
	foreach(target server client)
		target_link_options(${target} PRIVATE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
	endforeach()
endif()

# --- Testing ---
enable_testing()

# --- Unit tests ---
# The monolithic test binary exercises both client and server code, so it is
# the one place that legitimately sees both include directories and links both
# core libraries.  client_cli.c is compiled here directly (with the test build
# define) rather than linked from fastsync_client_core so its test-only shims
# and the absence of main() are preserved.
set(TEST_SRCS
	tests/runner.c
	tests/test_array_list.c
	tests/test_batch.c
	tests/test_change_list.c
	tests/test_checksum.c
	tests/test_chunk.c
	tests/test_client_cli.c
	tests/test_compression.c
	tests/test_config.c
	tests/test_credentials.c
	tests/test_daemon_conf.c
	tests/test_daemon_limits.c
	tests/test_data.c
	tests/test_delay_updates.c
	tests/test_delta.c
	tests/test_file.c
	tests/test_file_list.c
	tests/test_file_sendfile.c
	tests/test_format.c
	tests/test_fuzz_smoke.c
	tests/test_glob.c
	tests/test_hardlink.c
	tests/test_iconv.c
	tests/test_log.c
	tests/test_metadata.c
	tests/test_motd.c
	tests/test_multiprocessing.c
	tests/test_property.c
	tests/test_protocol.c
	tests/test_protocol_error.c
	tests/test_queue.c
	tests/test_receiver_timeout.c
	tests/test_robustness.c
	tests/test_scanner.c
	tests/test_server.c
	tests/test_server_cli.c
	tests/test_shared_utils.c
	tests/test_stop.c
	tests/test_stress.c
	tests/test_transport_ssh.c
	tests/test_transport_tcp.c
	tests/test_transport_tls.c
	tests/test_xattr.c
)

add_executable(tests ${TEST_SRCS} src/client/client_cli.c)
target_include_directories(tests PRIVATE tests)
target_compile_definitions(tests PRIVATE FASTSYNC_TEST_BUILD)
target_link_libraries(tests PRIVATE fastsync_server_core fastsync_client_core)
add_test(NAME unit_all COMMAND tests)

# --- Fuzz targets (requires clang) ---
option(ENABLE_FUZZ "Build fuzz targets (requires clang)" OFF)
if(ENABLE_FUZZ)
  if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "ENABLE_FUZZ requires Clang (compiler is ${CMAKE_C_COMPILER_ID})")
  endif()
	set(FUZZ_SRCS
		tests/fuzz/fuzz_chunk_deserialize.c
		tests/fuzz/fuzz_compress_decompress.c
		tests/fuzz/fuzz_config_receive.c
		tests/fuzz/fuzz_delta_deserialize.c
		tests/fuzz/fuzz_delta_signature_deserialize.c
		tests/fuzz/fuzz_glob_match.c
		tests/fuzz/fuzz_identity_parse.c
		tests/fuzz/fuzz_manifest.c
		tests/fuzz/fuzz_metadata_from_buf.c
		tests/fuzz/fuzz_protocol_framing.c
		tests/fuzz/fuzz_xattr_block.c
	)
	# Compile the sources under test directly so libFuzzer's coverage
	# instrumentation sees them (static libraries would be uninstrumented).
	set(FUZZ_CORE_SRCS ${SHARED_SRCS} src/server/receiver.c src/server/receiver_pipeline.c)
	foreach(FUZZ_SRC ${FUZZ_SRCS})
		get_filename_component(FUZZ_NAME ${FUZZ_SRC} NAME_WE)
		add_executable(${FUZZ_NAME} ${FUZZ_SRC} ${FUZZ_CORE_SRCS})
		target_include_directories(${FUZZ_NAME} PRIVATE tests src/shared src/server)
		target_compile_options(${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
		target_link_options(${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address,undefined)
		target_link_libraries(${FUZZ_NAME} PRIVATE Threads::Threads ${ZSTD_LIBRARY} OpenSSL::SSL
												  OpenSSL::Crypto xxhash)
	endforeach()
endif()
