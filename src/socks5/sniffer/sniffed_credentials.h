#ifndef PC_2020A_6_TPE_SOCKSV5_SNIFFED_CREDENTIALS_H
#define PC_2020A_6_TPE_SOCKSV5_SNIFFED_CREDENTIALS_H

#include <arpa/inet.h>

#define PORT_DIGITS 5

struct sniffed_credentials {
    char *datetime;
    char *username;
    const char *protocol;
    char destination[INET6_ADDRSTRLEN];
    char port[PORT_DIGITS + 1];
    char *logger_user;
    char *password;
};

typedef struct sniffed_credentials_CDT *sniffed_credentials_list;
typedef struct sniffed_credentials_node_CDT *sniffed_credentials_node;

sniffed_credentials_list sniffed_credentials_create_list();

void sniffed_credentials_add(sniffed_credentials_list list, struct sniffed_credentials *credentials);

sniffed_credentials_node sniffed_credentials_get_first(sniffed_credentials_list list);

sniffed_credentials_node sniffed_credentials_get_next(sniffed_credentials_node node);

struct sniffed_credentials *sniffed_credentials_get(sniffed_credentials_node node);

void sniffed_credentials_destroy(sniffed_credentials_list list);

#endif //PC_2020A_6_TPE_SOCKSV5_SNIFFED_CREDENTIALS_H
