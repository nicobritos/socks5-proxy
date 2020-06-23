#ifndef PC_2020A_6_TPE_SOCKSV5_CONFIGURATION_H
#define PC_2020A_6_TPE_SOCKSV5_CONFIGURATION_H

#include <stdbool.h>
#include <bits/socket.h>
#include <netinet/in.h>

#define DEFAULT_SOCKS_ADDR_FAMILY AF_INET6
#define DEFAULT_SOCKS_ADDR in6addr_any
#define DEFAULT_SOCKS_PORT 1080
#define DEFAULT_SOCKS_SNIFFER_ENABLED true

#define DEFAULT_MONITOR_ADDR_FAMILY AF_INET
#define DEFAULT_MONITOR_ADDR INADDR_LOOPBACK
#define DEFAULT_MONITOR_PORT 8080

#define DEFAULT_DOH_ADDR_FAMILY AF_INET
#define DEFAULT_DOH_ADDR INADDR_ANY // TODO
#define DEFAULT_DOH_PORT 8053
#define DEFAULT_DOH_DOMAIN "localhost"

struct {
    struct {
        struct sockaddr_storage sockaddr;
        char *domain_name;
        socklen_t socklen;
    } doh;

    struct {
        struct sockaddr_storage sockaddr;
        socklen_t socklen;
        bool sniffers_enabled;
    } socks5;

    struct {
        struct sockaddr_storage sockaddr;
        socklen_t socklen;
    } monitor;
} configuration;

#endif //PC_2020A_6_TPE_SOCKSV5_CONFIGURATION_H
