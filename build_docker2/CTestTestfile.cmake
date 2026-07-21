# CMake generated Testfile for 
# Source directory: /workspace
# Build directory: /workspace/build_docker2
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[unit_all]=] "/workspace/build_docker2/tests")
set_tests_properties([=[unit_all]=] PROPERTIES  _BACKTRACE_TRIPLES "/workspace/CMakeLists.txt;85;add_test;/workspace/CMakeLists.txt;0;")
subdirs("_deps/xxhash-build")
