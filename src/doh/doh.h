#ifndef DOH_H_
#define DOH_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include "doh_response_parser.h"


#define MAX_ADDR 6
#define DNS_SERVER_IP "127.0.0.1"
#define DNS_SERVER_IP6 "::1"
#define DNS_SERVER_AF AF_INET
#define DNS_SERVER_DOMAIN_NAME "localhost"
#define DNS_SERVER_PORT 80u
#define REQ_MAXSIZE 1024
#define MAXSTRINGLENGTH 128
#define DNS_BUFFER_SIZE 2048


// Devuelve el request HTTP correspondiete para realizar la consulta de name sobre Doh
char *getRequest(ssize_t *len, char *name, sa_family_t family, const char *dns_hostname);


#endif // DOH_H_
