cmake_minimum_required(VERSION 3.1)
project(PC-2020A-6-TPE.SOCKSV5)

set(CMAKE_C STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic -Wall -Wextra -std=c11 -Wno-unused-parameter -D_POSIX_C_SOURCE=200112L -fsanitize=address -g -D_GNU_SOURCE")
set(SOURCE_FILES
        src/utils/buffer.c
        src/utils/netutils.c
        src/utils/selector.c
        src/utils/stm.c
        src/socks5/socks5nio.c
        src/socks5/message/request.c
        src/socks5/message/parser/hello_parser.c
        src/socks5/message/parser/auth_user_pass_parser.c
        src/socks5/message/parser/request_parser.c
        src/socks5/message/auth_user_pass_helper.c
        src/socks5/sniffer/http_sniffer.c
        src/socks5/sniffer/pop3_sniffer.c
        src/utils/sorted_hashmap.c
        src/socks5/sniffer/sniffed_credentials.c
        src/utils/log_helper.c
        src/utils/byte_formatter.c
        src/args_helper.c
        src/doh/doh.c
        src/doh/doh_response_parser.c
        src/utils/parser.c
#        src/monitor/MonitorClient.c
        src/monitor/MonitorServer.c
        src/monitor/parser/server/command_request_parser.c
)

add_executable(PC-2020A-6-TPE.SOCKSV5 src/main.c ${SOURCE_FILES})

target_link_libraries(PC-2020A-6-TPE.SOCKSV5 -lsctp)
