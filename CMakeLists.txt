cmake_minimum_required(VERSION 3.29)
project(Notdns)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_COMPILER clang++-18)
set(CMAKE_EXPERIMENTAL_CXX_MODULE_DYNDEP 1)
set(CXX_SCAN_FOR_MODULES ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

add_executable(not_dns main.cpp)

add_subdirectory(src)
target_include_directories(not_dns PRIVATE src)
target_link_libraries(not_dns PRIVATE notD)