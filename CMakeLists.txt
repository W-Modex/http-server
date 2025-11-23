cmake_minimum_required(VERSION 3.10)
project(http-server)

add_executable(server src/server.c src/parser.c src/network.c src/clients.c)

include_directories(include)