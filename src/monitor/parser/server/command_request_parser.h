#ifndef COMMAND_REQUEST_PARSER_H_
#define COMMAND_REQUEST_PARSER_H_


/**
 * get_vars_parser.c -- parser de la respuesta del comando GET VARS (ver RFC)
 *
 * Permite extraer:
 *      1. La variable I/O timeout
 */
#include <stdint.h>
#include <stddef.h>
#include "../parser_errors.h"

typedef enum {
    GET_METRICS = 1,
    GET_USERS,
    GET_ACCESS_LOG,
    GET_PASSWORDS,
    GET_VARS,
    SET_USER,
    SET_VAR,
} command_code;

typedef enum {
    DISABLE_USER,
    ENABLE_USER,
    REMOVE_USER,
} user_mode;

typedef enum {
    SYSTEM_LOG = 2,
    SOCKS_LOG = 3
} var_code;


struct command {
    command_code code;
    char * user;
    char * password;
    user_mode mode;
    var_code var;
    uint8_t * var_value;
    size_t var_value_length;
    parser_error_t error;
};

/**
 * Dado un datagrama (array de bytes) de respuesta del comando GET USERS (ver RFC) para el proxy
 * y su longitud, parsea el datagrama.
 * Si no cumple con el RFC devuelve INVALID_INPUT_FORMAT_ERROR en el campo de error de la estructura.
 */
struct command * command_request_parser(uint8_t *s, size_t length);

/**
 * Libera la memoria utilizada por la estructura, si metrics es NULL, no hace nada
 */ 
void free_command(struct command *command);

#endif
