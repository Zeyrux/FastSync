cmake_minimum_required(VERSION 3.22)

project(FastFileTransfer)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -g -O3)

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

option(STRICT_WARNINGS "Enable strict warnings (Wextra, Wpedantic, Werror)" OFF)
if(STRICT_WARNINGS)
  add_compile_options(-Wextra -Wpedantic -Werror)
endif()

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

set(SHARED_SRCS
  src/shared/array_list.c
  src/shared/chunk.c
  src/shared/compression.c
  src/shared/config.c
  src/shared/data.c
  src/shared/delta.c
  src/shared/file.c
  src/shared/log.c
  src/shared/metadata.c
  src/shared/multiprocessing.c
  src/shared/protocol.c
  src/shared/queue.c
  src/shared/transport_ssh.c
  src/shared/transport_tcp.c
  src/shared/transport_tls.c
  src/shared/utils.c
)
set(SERVER_SRCS src/server/server.c)
set(CLIENT_SRCS
  src/client/client_cli.c
  src/client/client_send.c
  src/client/scanner.c
  src/client/usage.c
)

function(configure_fastsync_target target)
  target_include_directories(${target} PRIVATE src/shared src/server src/client)
  target_link_libraries(${target} PRIVATE Threads::Threads ${ZSTD_LIBRARY} OpenSSL::SSL OpenSSL::Crypto xxhash)
endfunction()

add_executable(server ${SERVER_SRCS} ${SHARED_SRCS})
configure_fastsync_target(server)
add_executable(client ${CLIENT_SRCS} ${SHARED_SRCS})
configure_fastsync_target(client)

enable_testing()
set(TEST_SRCS
  tests/runner.c
  tests/test_array_list.c
  tests/test_chunk.c
  tests/test_client_cli.c
  tests/test_compression.c
  tests/test_config.c
  tests/test_data.c
  tests/test_delta.c
  tests/test_file.c
  tests/test_file_sendfile.c
  tests/test_fuzz_smoke.c
  tests/test_glob.c
  tests/test_log.c
  tests/test_metadata.c
  tests/test_multiprocessing.c
  tests/test_property.c
  tests/test_protocol.c
  tests/test_queue.c
  tests/test_robustness.c
  tests/test_scanner.c
  tests/test_server.c
  tests/test_shared_utils.c
  tests/test_stress.c
  tests/test_transport_ssh.c
  tests/test_transport_tcp.c
  tests/test_transport_tls.c
)
add_executable(tests ${TEST_SRCS} ${SHARED_SRCS} src/client/scanner.c src/client/client_cli.c)
configure_fastsync_target(tests)
target_include_directories(tests PRIVATE tests)
target_compile_definitions(tests PRIVATE FASTSYNC_TEST_BUILD)
add_test(NAME unit_all COMMAND tests)

option(ENABLE_FUZZ "Build fuzz targets (requires clang)" OFF)
if(ENABLE_FUZZ)
  if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "ENABLE_FUZZ requires Clang (compiler is ${CMAKE_C_COMPILER_ID})")
  endif()
  set(FUZZ_SRCS
    tests/fuzz/fuzz_chunk_deserialize.c
    tests/fuzz/fuzz_compress_decompress.c
    tests/fuzz/fuzz_delta_deserialize.c
    tests/fuzz/fuzz_delta_signature_deserialize.c
    tests/fuzz/fuzz_glob_match.c
    tests/fuzz/fuzz_metadata_from_buf.c
  )
  foreach(FUZZ_SRC ${FUZZ_SRCS})
    get_filename_component(FUZZ_NAME ${FUZZ_SRC} NAME_WE)
    add_executable(${FUZZ_NAME} ${FUZZ_SRC} ${SHARED_SRCS})
    configure_fastsync_target(${FUZZ_NAME})
    target_include_directories(${FUZZ_NAME} PRIVATE tests)
    target_compile_options(${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
    target_link_options(${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address,undefined)
  endforeach()
endif()
