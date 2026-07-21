# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/workspace/build_docker2/_deps/xxhash-src"
  "/workspace/build_docker2/_deps/xxhash-build"
  "/workspace/build_docker2/_deps/xxhash-subbuild/xxhash-populate-prefix"
  "/workspace/build_docker2/_deps/xxhash-subbuild/xxhash-populate-prefix/tmp"
  "/workspace/build_docker2/_deps/xxhash-subbuild/xxhash-populate-prefix/src/xxhash-populate-stamp"
  "/workspace/build_docker2/_deps/xxhash-subbuild/xxhash-populate-prefix/src"
  "/workspace/build_docker2/_deps/xxhash-subbuild/xxhash-populate-prefix/src/xxhash-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/workspace/build_docker2/_deps/xxhash-subbuild/xxhash-populate-prefix/src/xxhash-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/workspace/build_docker2/_deps/xxhash-subbuild/xxhash-populate-prefix/src/xxhash-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
