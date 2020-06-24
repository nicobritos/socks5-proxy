#ifndef GET_VARS_PARSER_H_
#define GET_VARS_PARSER_H_

/**
 * get_vars_parser.c -- parser de la respuesta del comando GET VARS (ver RFC)
 *
 * Permite extraer:
 *      1. La variable I/O timeout
 */
#include <stdint.h>
#include <stddef.h>
#include "../parser_errors.h"
#include "../../../utils/log_helper.h"

struct vars {
    enum log_severity system_lmode, socks_lmode;
    parser_error_t error;
    struct parser *parser;
    size_t message_length;
    int finished;
};

struct vars * get_vars_parser_init();

/**
 * Dado un datagrama (array de bytes) de respuesta del comando GET USERS (ver RFC) para el proxy
 * y su longitud, parsea el datagrama.
 * Si no cumple con el RFC devuelve INVALID_INPUT_FORMAT_ERROR en el campo de error de la estructura.
 */
struct vars * get_vars_parser_consume(uint8_t *s, size_t length, struct vars * ans);

/**
 * Libera la memoria utilizada por la estructura, si metrics es NULL, no hace nada
 */ 
void free_vars(struct vars *vars);

#endif
