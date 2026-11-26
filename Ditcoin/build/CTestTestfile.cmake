# CMake generated Testfile for 
# Source directory: /home/dr-2/DR-2/AI/Trae/Blockchain_Bitcoin/Ditcoin
# Build directory: /home/dr-2/DR-2/AI/Trae/Blockchain_Bitcoin/Ditcoin/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(dtc_tests "/home/dr-2/DR-2/AI/Trae/Blockchain_Bitcoin/Ditcoin/build/dtc_tests")
set_tests_properties(dtc_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/dr-2/DR-2/AI/Trae/Blockchain_Bitcoin/Ditcoin/CMakeLists.txt;155;add_test;/home/dr-2/DR-2/AI/Trae/Blockchain_Bitcoin/Ditcoin/CMakeLists.txt;0;")
subdirs("vendor/secp256k1")
