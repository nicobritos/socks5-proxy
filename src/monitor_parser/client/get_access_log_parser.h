#ifndef GET_ACCESS_PARSER_H_
#define GET_ACCESS_PARSER_H_


/**
 * get_access_log_parser.c -- parser de la respuesta del comando GET ACCESS LOG (ver RFC).
 *
 * Permite extraer:
 *      1. Las entradas del log. Cada entrada contiene:
 *          a. El timestamp del acceso (Formato ISO-8601)
 *          b. El usuario (nombre y status)
 *          c. El IP de origen
 *          d. El puerto de origen
 *          e. El nombre del destino
 *          f. El puerto de destino
 */
#include <stdint.h>
#include <stddef.h>
#include "parser_errors.h"

typedef struct {
    char * user;
    uint8_t status;
} user;

typedef struct {
    char * time;
    user user;
    char * origin_ip;
    uint32_t origin_port;
    char * destination;
    uint32_t destination_port;
} entry;

struct access_log {
    entry * entries;
    size_t entry_qty;
    parser_error_t error;
};

/**
 * Dado un datagrama (array de bytes) de respuesta del comando GET ACCESS LOG (ver RFC) para el proxy
 * y su longitud, parsea el datagrama.
 * Si no cumple con el RFC devuelve INVALID_INPUT_FORMAT_ERROR en el campo de error de la estructura.
 */
struct access_log * get_access_log_parser(uint8_t *s, size_t length);

/**
 * Libera la memoria utilizada por la estructura, si metrics es NULL, no hace nada
 */ 
void free_access_log(struct access_log * users);


#endif
