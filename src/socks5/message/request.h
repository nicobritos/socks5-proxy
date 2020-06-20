#ifndef PC_2020A_6_TPE_SOCKSV5_REQUEST_HELPER_H
#define PC_2020A_6_TPE_SOCKSV5_REQUEST_HELPER_H

#include <arpa/inet.h>

#define REQUEST_CMD_CONNECT 0x01
#define REQUEST_CMD_BIND 0x02
#define REQUEST_CMD_UDP_ASSOCIATE 0x03
#define REQUEST_ATYP_IPV4 0x01
#define REQUEST_ATYP_DOMAIN_NAME 0x03
#define REQUEST_ATYP_IPV6 0x04

/**
 * [RFC1928]
 * -------------- REQUEST --------------
 *        o  VER    protocol version: X'05'
 *        o  CMD
 *           o  CONNECT X'01'
 *           o  BIND X'02'
 *           o  UDP ASSOCIATE X'03'
 *        o  RSV    RESERVED
 *        o  ATYP   address type of following address
 *           o  IP V4 address: X'01'
 *           o  DOMAINNAME: X'03'
 *           o  IP V6 address: X'04'
 *        o  DST.ADDR       desired destination address
 *        o  DST.PORT desired destination port in network octet
 *           order
 *
 *
 * -------------- RESPONSE --------------
 * REP    Reply field:
 *            o  X'00' succeeded
 *            o  X'01' general SOCKS server failure
 *            o  X'02' connection not allowed by ruleset
 *            o  X'03' Network unreachable
 *            o  X'04' Host unreachable
 *            o  X'05' Connection refused
 *            o  X'06' TTL expired
 *            o  X'07' Command not supported
 *            o  X'08' Address type not supported
 *            o  X'09' to X'FF' unassigned
 */

enum socks_response_status {
    socks_status_succeeded,
    socks_status_general_SOCKS_server_failure,
    socks_status_connection_not_allowed_by_ruleset,
    socks_status_network_unreachable,
    socks_status_host_unreachable,
    socks_status_connection_refused,
    socks_status_ttl_expired,
    socks_status_command_not_supported,
    socks_status_address_type_not_supported
};

struct request {
    struct sockaddr dest_addr;

    uint8_t address_type;
    uint16_t port;
    uint16_t cmd;

    char *domain_name;
};

/**
 * Devuelve un estado a partir de errno
 * @param e
 * @return socks_response_status
 */
enum socks_response_status errno_to_socks(int e);

/**
 * Devuelve un string que representa el estado
 */
const char *socks_response_status_str(enum socks_response_status status);

#endif //PC_2020A_6_TPE_SOCKSV5_REQUEST_HELPER_H
