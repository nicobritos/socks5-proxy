#ifndef AUTH_SERVER_RESPONSE_PARSER_H_
#define AUTH_SERVER_RESPONSE_PARSER_H_


/**
 * auth_server_response_parser.c -- parser de la respuesta de autentificacion para comunicacion con proxy.
 *
 * Permite extraer:
 *      1. El codigo de status
 *      2. El mensaje
 */
#include <stdint.h>
#include <stddef.h>
#include "../parser_errors.h"

struct auth_response {
    uint8_t status;
    char * message;
    parser_error_t error;
    struct parser * parser;
    size_t message_length;
    uint8_t finished;
};

struct auth_response * auth_response_parser_init();

/**
 * Dado un datagrama (array de bytes) de autentificacion para el proxy y su longitud, parsea el datagrama
 * Si no cumple con el RFC devuelve INVALID_INPUT_FORMAT_ERROR en el campo de error de la estructura.
 */
struct auth_response * auth_response_parser_consume(uint8_t *s, size_t length, struct auth_response * auth_response);

/**
 * Libera la memoria utilizada por la estructura, si auth_response es NULL, no hace nada
 */ 
void auth_response_free(struct auth_response * auth_response);


#endif
