#ifndef PC_2020A_6_TPE_SOCKSV5_SOCKS5NIO_H
#define PC_2020A_6_TPE_SOCKSV5_SOCKS5NIO_H

#include "../utils/selector.h"
#include "../utils/log_helper.h"
#include "sniffer/sniffed_credentials.h"

void socks_init();

/**
 * Devuelve el logger del socks o NULL si no esta inicializado
 * @return
 */
log_t socks_get_log();

/**
 * Devuelve la cantidad total de clientes que se conectaron
 * desde que se inicio el servidor
 * @return
 */
uint64_t socks_get_total_connections();

/**
 * Devuelve la cantidad de clientes conectados en el momento
 * @return
 */
uint64_t socks_get_current_connections();

/**
 * Devuelve la cantidad total de bytes transferidos (down + up)
 * @return
 */
uint64_t socks_get_total_bytes_transferred();

/**
 * Devuelve una lista de sniffed credentials
 * @return
 */
sniffed_credentials_list socks_get_sniffed_credentials_list();

void socks_pool_destroy();

void socks_passive_accept(struct selector_key *key);

#endif
