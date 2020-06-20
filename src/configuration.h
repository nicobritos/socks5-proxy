#ifndef PC_2020A_6_TPE_SOCKSV5_CONFIGURATION_H
#define PC_2020A_6_TPE_SOCKSV5_CONFIGURATION_H

struct {
    struct {
        struct sockaddr_storage sockaddr;
        char *domain_name;
        socklen_t socklen;
    } doh;
} configuration;

#endif //PC_2020A_6_TPE_SOCKSV5_CONFIGURATION_H
