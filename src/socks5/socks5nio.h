#ifndef PC_2020A_6_TPE_SOCKSV5_SOCKS5NIO_H
#define PC_2020A_6_TPE_SOCKSV5_SOCKS5NIO_H

#include "../utils/selector.h"
#include "../utils/log_helper.h"
#include "sniffer/sniffed_credentials.h"

#define PORT_DIGITS 5

struct socks_access_log_details_t {
    char *datetime;
    char *username;

    struct {
        char ip[INET6_ADDRSTRLEN];
        char port[PORT_DIGITS + 1];
    } origin;

    struct {
        char *name;
        char port[PORT_DIGITS + 1];
    } destination;
};

typedef struct socks_access_log_node_CDT *socks_access_log_node_t;

void socks_init();

/**
 * Devuelve el logger del socks o NULL si no esta inicializado
 * @return
 */
log_t socks_get_log();

/**
 * Devuelve el primer nodo del access log
 * @return
 */
socks_access_log_node_t socks_get_first_access_log_node();

/**
 * Devuelve el siguiente nodo del access log
 * @param node
 * @return
 */
socks_access_log_node_t socks_get_next_access_log_node(socks_access_log_node_t node);

/**
 * Devuelve el access log asociado al nodo
 * @param node
 * @return
 */
struct socks_access_log_details_t *socks_get_access_log(socks_access_log_node_t node);

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
