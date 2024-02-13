cmake_minimum_required(VERSION 3.10)
project(client_test)

set(CMAKE_C_STANDARD 11)

include_directories(inc)

set(SOURCE_FILES
        src/boot_proc.c
        src/command_proc.c
        src/deserialize.c
        src/encrypt_payload.c
        src/main.c
        src/mq_recv.c
        src/mq_send.c
        src/serialize.c)

add_executable(client_test ${SOURCE_FILES})

target_link_libraries(client_test crypto)