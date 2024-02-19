cmake_minimum_required(VERSION 3.10)
project(server_test)

set(CMAKE_C_STANDARD 11)

include_directories(inc)

set(SOURCE_FILES
        src/deserialize_tlv.c
        src/do_op.c
        src/key_derivation.c
        src/main.c
        src/mq_recv.c
        src/mq_send.c
        src/crypto_operation.c
        src/serialize.c)

add_executable(server_test ${SOURCE_FILES})

target_link_libraries(server_test crypto)