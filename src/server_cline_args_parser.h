#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>


typedef struct server_cline_args {
    char *address;
    uint16_t port;
    uint16_t version;
} server_cline_args;

typedef server_cline_args *server_args_ptr;