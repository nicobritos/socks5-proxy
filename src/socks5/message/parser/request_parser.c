#include "request_parser.h"

#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#define VALID_VERSION 0x05
#define VALID_RESERVED 0x00

#define IPV4_LENGTH 4
#define IPV6_LENGTH 16

#define MIN_REPLY_SIZE 6 // VER + REP + RSV + ATYP + BND.PORT

/** inicializa el parser */
void request_parser_init(struct request_parser *p) {
    if (p->request == NULL) {
        p->_state = request_error_missing_request;
    } else {
        p->_state = request_ver;
        p->request->port = p->request->cmd = p->request->address_type = 0;
    }
    p->_address_index = p->_address_length = p->_port_index = 0;
}

/** entrega un byte al parser. retorna el nuevo estado del parser, o el mismo si no hubo cambios */
enum request_state request_parser_feed(struct request_parser *p, uint8_t b) {
    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;

    switch (p->_state) {
        case request_ver:
            p->_state = b == VALID_VERSION ? p->_state = request_cmd : request_error_invalid_version;
            break;
        case request_cmd:
            if (b != REQUEST_CMD_CONNECT && b != REQUEST_CMD_BIND && b != REQUEST_CMD_UDP_ASSOCIATE) {
                p->_state = request_error_invalid_cmd;
            } else {
                p->_state = request_rsv;
                p->request->cmd = b;
            }
            break;
        case request_rsv:
            if (b != VALID_RESERVED)
                p->_state = request_error_invalid_rsv;
            else
                p->_state = request_atyp;
            break;
        case request_atyp:
            if (b != REQUEST_ATYP_DOMAIN_NAME && b != REQUEST_ATYP_IPV4 && b != REQUEST_ATYP_IPV6) {
                p->_state = request_error_invalid_atyp;
            } else {
                p->_state = request_dst_addr;
                p->request->address_type = b;
            }
            break;
        case request_dst_addr:
            switch (p->request->address_type) {
                case REQUEST_ATYP_IPV4:
                    in = (struct sockaddr_in *) &p->request->dest_addr;

                    if (p->_address_length == 0) {
                        in->sin_family = AF_INET;
                        in->sin_addr.s_addr = 0;
                        p->_address_length = IPV4_LENGTH;

                        p->_address_index = 0;
                    }

                    in->sin_addr.s_addr |= (((uint32_t) b) << (8u * (3 - p->_address_index)));
                    p->_address_index++;
                    if (p->_address_index == p->_address_length) {
                        in->sin_addr.s_addr = htonl(in->sin_addr.s_addr);
                        p->_state = request_dst_port;
                    }
                    break;
                case REQUEST_ATYP_IPV6:
                    in6 = (struct sockaddr_in6 *) &p->request->dest_addr;

                    if (p->_address_length == 0) {
                        in6->sin6_family = AF_INET6;
                        p->_address_length = IPV6_LENGTH;

                        p->_address_index = 0;
                    }

                    in6->sin6_addr.s6_addr[p->_address_index++] = b;
                    if (p->_address_index == p->_address_length) {
                        p->_state = request_dst_port;
                    }
                    break;
                case REQUEST_ATYP_DOMAIN_NAME:
                    if (p->_address_length == 0) {
                        if (b == 0)
                            return p->_state = request_error_invalid_domain_address;

                        p->request->domain_name = calloc(b + 1, sizeof(*p->request->domain_name));
                        if (p->request->domain_name == NULL)
                            return p->_state = request_error_no_memory;

                        p->_address_length = b;
                        p->_address_index = 0;
                    } else {
                        // El primer byte es el largo, no forma parte del domain name
                        p->request->domain_name[p->_address_index++] = b;
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
                p->request->port = b << 8u;
            } else {
                p->request->port |= b;
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
        case request_error_missing_request:
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
        || state == request_error_no_memory
        || state == request_error_missing_request) {
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
        case request_error_invalid_cmd:
            return "error: comando invalido";
        case request_error_invalid_rsv:
            return "error: rsv byte en la request invalido";
        case request_error_invalid_atyp:
            return "error: tipo de address en la request invalido";
        case request_error_invalid_version:
            return "error: version en la request invalida";
        case request_error_no_memory:
            return "error: no hay memoria para parsear la request";
        case request_error_invalid_domain_address:
            return "error: invalid domain address";
        default:
            return "desconocido";
    }
}

const char *request_parser_str(const struct request_parser *p) {
    switch (p->_state) {
        case request_ok:
            return "exitoso";
        default:
            return request_parser_error(p);
    }
}

/** libera recursos internos del parser */
void request_parser_close(struct request_parser *p) {
    if (p->request != NULL && p->request->address_type == REQUEST_ATYP_DOMAIN_NAME) {
        if (p->request->domain_name != NULL) {
            free(p->request->domain_name);
            p->request->domain_name = NULL;
        }
    }
}

/**
 * serializa en buffer la respuesta del parser.
 *
 * @return la cantidad de bytes ocupados del buffer o -1 si no había
 * espacio suficiente.
 */
int request_parser_write_response(
        buffer *buffer,
        const struct sockaddr_storage *client_addr,
        const uint8_t reply)
{
    size_t n;
    uint8_t *buff = buffer_write_ptr(buffer, &n);
    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;

    uint16_t length = MIN_REPLY_SIZE + (client_addr->ss_family == AF_INET ? IPV4_LENGTH : IPV6_LENGTH);
    if (n < length) return -1;

    uint16_t i = 0;
    uint16_t address_i = 0;

    buff[i++] = VALID_VERSION;
    buff[i++] = reply;
    buff[i++] = VALID_RESERVED;

    if (client_addr->ss_family != AF_INET6) {
        in = (struct sockaddr_in *) client_addr;
        buff[i++] = REQUEST_ATYP_IPV4;

        /**
         * No importa la IP. Si indicamos 0.0.0.0 entonces el cliente entiendie
         * que la IP bindeada al mismo es la misma IP que uso para conectarse
         * a este servidor
         * @see https://stackoverflow.com/questions/39990056/why-server-reply-of-socks5-protocol-can-use-dummy-values
         */
        while (address_i < IPV4_LENGTH) {
            buff[i++] = 0;
            address_i++;
        }

        uint16_t port = htons(in->sin_port);
        buff[i++] = port >> 8u;
        buff[i] = port & 0xFFu;
    } else {
        in6 = (struct sockaddr_in6 *) client_addr;
        buff[i++] = REQUEST_ATYP_IPV6;

        /**
         * No importa la IP. Si indicamos 0.0.0.0 entonces el cliente entiende
         * que la IP bindeada al mismo es la misma IP que uso para conectarse
         * a este servidor
         * @see https://stackoverflow.com/questions/39990056/why-server-reply-of-socks5-protocol-can-use-dummy-values
         */
        while (address_i < IPV6_LENGTH) {
            buff[i++] = 0;
            address_i++;
        }

        uint16_t port = htons(in6->sin6_port);
        buff[i++] = port >> 8u;
        buff[i] = port & 0xFFu;
    }

    buffer_write_adv(buffer, length);
    return length;
}
