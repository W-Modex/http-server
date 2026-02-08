add_executable(test_http_parse test_http_parse.c)
target_link_libraries(test_http_parse PRIVATE myserver_lib)

add_test(NAME http_parse_test COMMAND test_http_parse)

add_executable(test_http_response test_http_response.c)
target_link_libraries(test_http_response PRIVATE myserver_lib)

add_test(NAME http_response_test COMMAND test_http_response)

add_executable(test_http_body test_http_body.c)
target_link_libraries(test_http_body PRIVATE myserver_lib)

add_test(NAME http_body_test COMMAND test_http_body)

add_executable(test_cookie_parse test_cookie_parse.c)
target_link_libraries(test_cookie_parse PRIVATE myserver_lib)

add_test(NAME cookie_parse_test COMMAND test_cookie_parse)

add_executable(test_csrf test_csrf.c)
target_link_libraries(test_csrf PRIVATE myserver_lib)

add_test(NAME csrf_test COMMAND test_csrf)

add_executable(test_oauth test_oauth.c)
target_link_libraries(test_oauth PRIVATE myserver_lib)

add_test(NAME oauth_test COMMAND test_oauth)
