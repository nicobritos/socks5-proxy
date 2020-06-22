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

typedef enum{
    DEBUG,
    INFO,
    WARNING,
    ERROR,
} logger_severity_mode;

struct vars {
    size_t io_timeout;
    logger_severity_mode lmode;
    parser_error_t error;
};

/**
 * Dado un datagrama (array de bytes) de respuesta del comando GET USERS (ver RFC) para el proxy
 * y su longitud, parsea el datagrama.
 * Si no cumple con el RFC devuelve INVALID_INPUT_FORMAT_ERROR en el campo de error de la estructura.
 */
struct vars * get_vars_parser(uint8_t *s, size_t length);

/**
 * Libera la memoria utilizada por la estructura, si metrics es NULL, no hace nada
 */ 
void free_vars(struct vars *vars);

#endif
