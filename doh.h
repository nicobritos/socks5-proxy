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

struct http_response * getIpbyName(uint8_t * hostname);

#endif // DOH_H_
