cmake_minimum_required(VERSION 3.23)
project(server)

find_package(OpenSSL REQUIRED)
find_package(PostgreSQL REQUIRED)

add_library(myserver_lib
    src/db/db.c
    src/db/db_ctx.c
    src/net/clients.c
    src/net/socket.c
    src/worker.c
    src/http/response.c
    src/http/request.c
    src/http/body.c
    src/router/router.c
    src/router/handlers.c
    src/auth/crypto.c
    src/auth/oauth.c
    src/auth/cookie.c
    src/auth/csrf.c
    src/auth/session.c
)

target_include_directories(myserver_lib PUBLIC include)
target_compile_definitions(myserver_lib PUBLIC STATIC_DIR="${CMAKE_SOURCE_DIR}/static")
target_link_libraries(myserver_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto PostgreSQL::PostgreSQL)

add_executable(server src/main.c)
target_link_libraries(server PRIVATE myserver_lib PostgreSQL::PostgreSQL)

enable_testing()
add_subdirectory(tests)
