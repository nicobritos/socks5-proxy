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

typedef enum errors{
    NO_ERROR,
    INVALID_INPUT_FORMAT_ERROR,  // Si el datagrama no cumple el formato del RFC
    REALLOC_ERROR,               // Si al hacer un realloc se produjo algun error
}auth_server_parser_error_t;

struct auth_response {
    uint8_t status;
    char * message;
    auth_server_parser_error_t error;
};

/**
 * Dado un datagrama (array de bytes) de autentificacion para el proxy y su longitud, parsea el datagrama
 * Si no cumple con el RFC devuelve INVALID_INPUT_FORMAT_ERROR en el campo de error de la estructura.
 */
struct auth_response * auth_response_parser(uint8_t *s, size_t length);

/**
 * Libera la memoria utilizada por la estructura, si auth_response es NULL, no hace nada
 */ 
void auth_response_free(struct auth_response * auth_response);


#endif
