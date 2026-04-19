cmake_minimum_required(VERSION 3.15)
project(dll_pack C)

set(CMAKE_C_STANDARD 11)

# Build validator DLL
add_subdirectory(src/validator)

# Build packer executable
add_subdirectory(src/packer)
