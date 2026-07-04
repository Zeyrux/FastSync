cmake_minimum_required(VERSION 4.1)

project(FastFileTransfer)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -g -O3)
# add_compile_options(-Wall -g -O1 -fsanitize=address)

# add_link_options(-fsanitize=address)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

find_library(ZSTD_LIBRARY zstd)
if(NOT ZSTD_LIBRARY)
	message(FATAL_ERROR "zstd library not found. Ensure it is in your nix-shell!")
endif()

file(GLOB SHARED_SRCS "src/shared/*.c")
file(GLOB SERVER_SRCS "src/server/*.c")
file(GLOB CLIENT_SRCS "src/client/*.c")
file(GLOB TEST_SRCS "tests/*.c")

add_executable(server ${SERVER_SRCS} ${SHARED_SRCS})
target_include_directories(server PRIVATE src/shared src/server src/client)
target_link_libraries(server PRIVATE Threads::Threads ${ZSTD_LIBRARY})

add_executable(client ${CLIENT_SRCS} ${SHARED_SRCS})
target_include_directories(client PRIVATE src/shared src/server src/client)
target_link_libraries(client PRIVATE Threads::Threads ${ZSTD_LIBRARY})

add_executable(tests ${TEST_SRCS} ${SHARED_SRCS})
target_include_directories(tests PRIVATE tests src/shared src/server src/client)
target_link_libraries(tests PRIVATE Threads::Threads ${ZSTD_LIBRARY})

