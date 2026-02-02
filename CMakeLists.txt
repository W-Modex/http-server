cmake_minimum_required(VERSION 3.23)
project(server)

find_package(OpenSSL REQUIRED)

add_library(myserver_lib
    src/net/clients.c
    src/net/socket.c
    src/worker.c
    src/http/response.c
    src/http/request.c
    src/http/body.c
    src/router/router.c
    src/router/handlers.c
    src/auth/crypto.c
    src/auth/cookie.c
    src/auth/session.c
)

target_include_directories(myserver_lib PUBLIC include)
target_link_libraries(myserver_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto)

add_executable(server src/main.c)
target_link_libraries(server PRIVATE myserver_lib)

enable_testing()
add_subdirectory(tests)
