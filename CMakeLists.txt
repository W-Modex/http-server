cmake_minimum_required(VERSION 3.23)
project(server)

add_library(myserver_lib
    src/clients.c
    src/network.c
    src/worker.c
    src/http_response.c
    src/http_parser.c
)

target_include_directories(myserver_lib PUBLIC include)

add_executable(server src/main.c)
target_link_libraries(server PRIVATE myserver_lib)

enable_testing()
add_subdirectory(tests)