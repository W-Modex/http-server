
add_executable(test_basic test_basic.c)
target_link_libraries(test_basic PRIVATE myserver_lib)

add_test(NAME basic_test COMMAND test_basic)


add_executable(test_http_parse test_http_parse.c)
target_link_libraries(test_http_parse PRIVATE myserver_lib)

add_test(NAME http_parse_test COMMAND test_http_parse)

add_executable(test_http_response test_http_response.c)
target_link_libraries(test_http_response PRIVATE myserver_lib)

add_test(NAME http_response_test COMMAND test_http_response)