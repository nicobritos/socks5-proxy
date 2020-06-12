//
// Created by Nico on 009, June 9, 2020.
//

#ifndef PC_2020A_6_TPE_SOCKSV5_REQUEST_PARSER_H
#define PC_2020A_6_TPE_SOCKSV5_REQUEST_PARSER_H

#include <stdint.h>
#include <stdbool.h>

#include "../../../utils/buffer.h"
#include "../request.h"

/**
 * ---------------------- REQUEST ----------------------
 * Once the method-dependent subnegotiation has completed, the client
 * sends the request details.  If the negotiated method includes
 * encapsulation for purposes of integrity checking and/or
 * confidentiality, these requests MUST be encapsulated in the method-
 * dependent encapsulation.
 *
 * The SOCKS request is formed as follows:
 *
 *      +----+-----+-------+------+----------+----------+
 *      |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *      +----+-----+-------+------+----------+----------+
 *      | 1  |  1  | X'00' |  1   | Variable |    2     |
 *      +----+-----+-------+------+----------+----------+
 *
 *   Where:
 *
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
 * The SOCKS server will typically evaluate the request based on source
 * and destination addresses, and return one or more reply messages, as
 * appropriate for the request type.
 *
 * In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies
 * the type of address contained within the field:
 *
 *        o  X'01'
 *
 * the address is a version-4 IP address, with a length of 4 octets
 *
 *        o  X'03'
 *
 * the address field contains a fully-qualified domain name.  The first
 * octet of the address field contains the number of octets of name that
 * follow, there is no terminating NUL octet.
 *
 *        o  X'04'
 *
 * the address is a version-6 IP address, with a length of 16 octets.
 *
 *
 */

/**
 * ---------------------- RESPONSE ----------------------
 * The SOCKS request information is sent by the client as soon as it has
 * established a connection to the SOCKS server, and completed the
 * authentication negotiations.  The server evaluates the request, and
 * returns a reply formed as follows:
 *
 *      +----+-----+-------+------+----------+----------+
 *      |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 *      +----+-----+-------+------+----------+----------+
 *      | 1  |  1  | X'00' |  1   | Variable |    2     |
 *      +----+-----+-------+------+----------+----------+
 *
 *   Where:
 *
 *        o  VER    protocol version: X'05'
 *        o  REP    Reply field:
 *           o  X'00' succeeded
 *           o  X'01' general SOCKS server failure
 *           o  X'02' connection not allowed by ruleset
 *           o  X'03' Network unreachable
 *           o  X'04' Host unreachable
 *           o  X'05' Connection refused
 *           o  X'06' TTL expired
 *           o  X'07' Command not supported
 *           o  X'08' Address type not supported
 *           o  X'09' to X'FF' unassigned
 *        o  RSV    RESERVED
 *        o  ATYP   address type of following address
 *           o  IP V4 address: X'01'
 *           o  DOMAINNAME: X'03'
 *           o  IP V6 address: X'04'
 *        o  BND.ADDR       server bound address
 *        o  BND.PORT       server bound port in network octet order
 *
 * Fields marked RESERVED (RSV) must be set to X'00'.
 *
 * If the chosen method includes encapsulation for purposes of
 * authentication, integrity and/or confidentiality, the replies are
 * encapsulated in the method-dependent encapsulation.
 */

/** estado del parser */
enum request_state {
    /** En este estado leeremos la version */
    request_ver,
    /** En este estado leeremos el comando */
    request_cmd,
    /** En este estado leeremos el campo reserved */
    request_rsv,
    /** En este estado leeremos el campo ATYP que indica el tipo de direccion pasada */
    request_atyp,
    /** En este estado leeremos la direccion */
    request_dst_addr,
    /** En este estado leeremos el puerto */
    request_dst_port,

    /** Estados terminales */
    request_ok,
    request_error_invalid_version,
    request_error_invalid_cmd,
    request_error_invalid_rsv,
    request_error_no_memory,
    request_error_missing_request,
    request_error_invalid_atyp,
    request_error_invalid_domain_address,
};

struct request_parser {
    /** Este campo es responsabilidad del usuario. Debe existir */
    struct request *request;

    /** Private */
    enum request_state _state;

    uint8_t _cmd;
    uint8_t _atyp;
    uint8_t _port_index;

    uint8_t _address_index;
    uint8_t _address_length;
};

/** inicializa el parser */
void request_parser_init(struct request_parser *p);

/** entrega un byte al parser. retorna el nuevo estado del parser, o el mismo si no hubo cambios */
enum request_state request_parser_feed(struct request_parser *p, uint8_t b);

/**
 * por cada elemento del buffer llama a `request_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum request_state request_parser_consume(buffer *b, struct request_parser *p, bool *errored);

/**
 * Permite distinguir a quien usa request_parser_feed si debe seguir
 * enviando caracters o no.
 *
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool request_parser_is_done(enum request_state state, bool *errored);

/**
 * En caso de que se haya llegado a un estado de error, permite obtener una
 * representación textual que describe el problema
 */
const char *request_parser_error(const struct request_parser *p);

/** libera recursos internos del parser */
void request_parser_close(struct request_parser *p);

/**
 * serializa en buffer la respuesta del parser.
 *
 * @return la cantidad de bytes ocupados del buffer o -1 si no había
 * espacio suficiente.
 */
int request_parser_write_response(buffer *buffer, const struct request_parser *p, const uint8_t reply);

#endif //PC_2020A_6_TPE_SOCKSV5_REQUEST_PARSER_H
