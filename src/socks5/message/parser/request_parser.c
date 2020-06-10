//
// Created by Nico on 009, June 9, 2020.
//

#include "request_parser.h"

#include <stdlib.h>
#include <stdio.h>

#define VALID_VERSION 0x05
#define VALID_RESERVED 0x00
#define CMD_CONNECT 0x01
#define CMD_BIND 0x02
#define CMD_UDP_ASSOCIATE 0x03
#define ATYP_IPV4 0x01
#define ATYP_DOMAIN_NAME 0x03
#define ATYP_IPV6 0x04

#define IPV4_LENGTH 4
#define IPV6_LENGTH 16

#define MIN_REPLY_SIZE 6 // VER + REP + RSV + ATYP + BND.PORT

/** inicializa el parser */
void request_parser_init(struct request_parser *p) {
    p->_state = request_ver;
    p->_address_index = p->_address_length = 0;
    p->_atyp = p->cmd = p->_port = p->_port_index = 0;
}

/** entrega un byte al parser. retorna el nuevo estado del parser, o el mismo si no hubo cambios */
enum request_state request_parser_feed(struct request_parser *p, uint8_t b) {
    switch (p->_state) {
        case request_ver:
            p->_state = b == VALID_VERSION ? p->_state = request_cmd : request_error_invalid_version;
            break;
        case request_cmd:
            if (b != CMD_CONNECT && b != CMD_BIND && b != CMD_UDP_ASSOCIATE) {
                p->_state = request_error_invalid_cmd;
            } else {
                p->_state = request_rsv;
                p->cmd = b;
            }
            break;
        case request_rsv:
            if (b != VALID_RESERVED)
                p->_state = request_error_invalid_rsv;
            else
                p->_state = request_atyp;
            break;
        case request_atyp:
            if (b != ATYP_DOMAIN_NAME && b != ATYP_IPV4 && b != ATYP_IPV6) {
                p->_state = request_error_invalid_atyp;
            } else {
                p->_state = request_dst_addr;
                p->_atyp = b;
            }
            break;
        case request_dst_addr:
            switch (p->_atyp) {
                case ATYP_IPV4:
                    if (p->_address_length == 0) {
                        p->_address.ipv4 = malloc(IPV4_LENGTH * sizeof(*p->_address.ipv4));
                        if (p->_address.ipv4 == NULL)
                            return p->_state = request_error_no_memory;

                        p->_address_length = IPV4_LENGTH;
                        p->_address_index = 0;
                    }

                    p->_address.ipv4[p->_address_index++] = b;
                    if (p->_address_index == p->_address_length) {
                        p->_state = request_dst_port;
                    }
                    break;
                case ATYP_IPV6:
                    if (p->_address_length == 0) {
                        p->_address.ipv6 = malloc(IPV6_LENGTH * sizeof(*p->_address.ipv6));
                        if (p->_address.ipv6 == NULL)
                            return p->_state = request_error_no_memory;

                        p->_address_length = IPV6_LENGTH;
                        p->_address_index = 0;
                    }

                    p->_address.ipv6[p->_address_index++] = b;
                    if (p->_address_index == p->_address_length) {
                        p->_state = request_dst_port;
                    }
                    break;
                case ATYP_DOMAIN_NAME:
                    if (p->_address_length == 0) {
                        if (b == 0)
                            return p->_state = request_error_invalid_domain_address;

                        p->_address.domain = malloc(b * sizeof(*p->_address.domain));
                        if (p->_address.domain == NULL)
                            return p->_state = request_error_no_memory;

                        p->_address_length = b;
                        p->_address_index = 0;
                    } else {
                        // El primer byte es el largo, no forma parte del domain name
                        p->_address.domain[p->_address_index++] = b;
                        if (p->_address_index == p->_address_length) {
                            p->_state = request_dst_port;
                        }
                    }
                    break;
                default:
                    p->_state = request_error_invalid_atyp;
            }
            break;
        case request_dst_port:
            if (p->_port_index == 0) {
                p->_port = b << 8u;
            } else {
                p->_port |= b;
            }
            p->_port_index++;
            if (p->_port_index == 2) {
                p->_state = request_ok;
            }
            break;
        case request_ok:
        case request_error_invalid_domain_address:
        case request_error_no_memory:
        case request_error_invalid_atyp:
        case request_error_invalid_cmd:
        case request_error_invalid_version:
        case request_error_invalid_rsv:
            break;
        default:
            fprintf(stderr, "unknown request_parser state %d\n", p->_state);
            abort();
    }

    return p->_state;
}

/**
 * por cada elemento del buffer llama a `request_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum request_state request_parser_consume(buffer *b, struct request_parser *p, bool *errored) {
    enum request_state st = p->_state;

    while (!request_parser_is_done(st, errored) && buffer_can_read(b)) {
        st = request_parser_feed(p, buffer_read(b));
    }
    return st;
}

/**
 * Permite distinguir a quien usa request_parser_feed si debe seguir
 * enviando caracters o no.
 *
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool request_parser_is_done(enum request_state state, bool *errored) {
    if (state == request_ok)
        return true;
    if (state == request_error_invalid_version
        || state == request_error_invalid_cmd
        || state == request_error_invalid_rsv
        || state == request_error_invalid_domain_address
        || state == request_error_invalid_atyp
        || state == request_error_no_memory) {
        if (errored != NULL)
            *errored = true;
        return true;
    }
    return false;
}

/**
 * En caso de que se haya llegado a un estado de error, permite obtener una
 * representación textual que describe el problema
 */
const char *request_parser_error(const struct request_parser *p) {
    switch (p->_state) {
        case request_error_no_memory:
            return "no memory available";
        case request_error_invalid_domain_address:
            return "invalid domain address";
        case request_error_invalid_version:
            return "invalid version number";
        case request_error_invalid_atyp:
            return "invalid ATYP value";
        case request_error_invalid_rsv:
            return "invalid RSV value";
        case request_error_invalid_cmd:
            return "invalid CMD value";
        default:
            return "";
    }
}

/** libera recursos internos del parser */
void request_parser_close(struct request_parser *p) {
    if (p->_atyp == ATYP_IPV4) {
        if (p->_address.ipv4 != NULL) free(p->_address.ipv4);
    } else if (p->_atyp == ATYP_IPV6) {
        if (p->_address.ipv6 != NULL) free(p->_address.ipv6);
    } else if (p->_atyp == ATYP_DOMAIN_NAME) {
        if (p->_address.domain != NULL) free(p->_address.domain);
    }
}

/**
 * serializa en buffer la respuesta del parser.
 *
 * @return la cantidad de bytes ocupados del buffer o -1 si no había
 * espacio suficiente.
 */
int request_parser_close_write_response(buffer *buffer, const struct request_parser *p, const uint8_t reply) {
    size_t n;
    uint8_t *buff = buffer_write_ptr(buffer, &n);
    /** Si estamos con un domain name, necesitamos un byte mas para especificar el largo */
    uint16_t length = MIN_REPLY_SIZE + p->_address_length + (p->_atyp == ATYP_DOMAIN_NAME ? 1 : 0);
    if (n < length) return -1;

    uint16_t i = 0, address_i = 0;
    buff[i++] = VALID_VERSION;
    buff[i++] = reply;
    buff[i++] = VALID_RESERVED;
    buff[i++] = p->_atyp;
    if (p->_atyp == ATYP_DOMAIN_NAME) {
        buff[i++] = p->_address_length;
        while (address_i < p->_address_length) {
            buff[i++] = p->_address.domain[address_i++];
        }
    } else if (p->_atyp == ATYP_IPV4) {
        while (address_i < p->_address_length) {
            buff[i++] = p->_address.ipv4[address_i++];
        }
    } else if (p->_atyp == ATYP_IPV6) {
        while (address_i < p->_address_length) {
            buff[i++] = p->_address.ipv6[address_i++];
        }
    }
    buff[i++] = (p->_port >> 8u);
    buff[i] = (p->_port & 0xFFu);

    buffer_write_adv(buffer, length);
    return length;
}
