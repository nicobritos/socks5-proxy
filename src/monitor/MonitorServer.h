//
// Created by Nacho Grasso on 07/06/2020.
//

#ifndef PC_2020A_6_SCTPSERVER_H
#define PC_2020A_6_SCTPSERVER_H

#include "../utils/selector.h"

void monitor_passive_accept(struct selector_key *key);

void monitor_pool_destroy();


#endif //PC_2020A_6_SCTPSERVER_H
