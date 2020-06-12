#ifndef PC_2020A_6_TPE_SOCKSV5_SOCKS5NIO_H
#define PC_2020A_6_TPE_SOCKSV5_SOCKS5NIO_H

#include "../utils/selector.h"

void socksv5_pool_destroy();

void socksv5_passive_accept(struct selector_key *key);

#endif
