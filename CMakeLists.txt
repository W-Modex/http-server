cmake_minimum_required(VERSION 3.23)
project(http-server)

add_executable(server src/main.c src/http_parser.c src/network.c src/clients.c src/http_response.c src/worker.c)

include_directories(include)