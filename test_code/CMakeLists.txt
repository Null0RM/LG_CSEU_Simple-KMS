cmake_minimum_required(VERSION 3.0)

project(
    cmakeProj
    VERSION 0.1
    LANGUAGES C
)

add_library(shape STATIC ${CMAKE_SOURCE_DIR}/)
target_compile_options(program PUBLIC -Wall -Wextra -Werror) #compile option
target_include_directories(program PUBLIC ${CMAKE_SOURCE_DIR}/inc)
add_executable(program cmakeTest.c) #executable file generate
