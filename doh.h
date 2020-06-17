#ifndef DOH_H_
#define DOH_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "http_response_parser.h"



#define MAX_ADDR 6
#define DNS_SERVER_IP "127.0.0.1"
#define DNS_SERVER_PORT 80
#define IPV4_VER 0
#define IPV6_VER 1
#define REQ_MAXSIZE 1024
#define MAXSTRINGLENGTH 128
#define BUFSIZE 2048



// Devuelve el request HTTP correspondiete para realizar la consulta de name sobre Doh
uint8_t * getRequest (ssize_t * len, uint8_t * name, int ip_ver);


#endif // DOH_H_
