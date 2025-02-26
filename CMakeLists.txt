cmake_minimum_required(VERSION 3.27)
project(dedupe)

set(CMAKE_CXX_STANDARD 17)
find_package(OpenSSL)

add_executable(dedupe main.cpp)
target_link_libraries(dedupe PRIVATE OpenSSL::Crypto)