cmake_minimum_required (VERSION 2.6)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -pedantic")

project (lithiumTNC)
add_executable(lithiumTNC main.c)
