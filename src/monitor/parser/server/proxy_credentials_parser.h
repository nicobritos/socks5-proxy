#ifndef PROXY_CREDENTIALS_PARSER_H_
#define PROXY_CREDENTIALS_PARSER_H_


/**
 * proxy_credentials_parser.c -- parser de autentificacion para comunicacion con proxy.
 *
 * Permite extraer:
 *      1. La versión
 *      2. El usuario
 *      3. La contraseña
 */
#include <stdint.h>
#include <stddef.h>
#include "../parser_errors.h"

struct proxy_credentials {
    uint8_t version;
    char * username;
    char * password;
    parser_error_t error;
    struct parser *parser;
    size_t username_length;
    size_t password_length;
    uint8_t finished;
};

struct proxy_credentials * proxy_credentials_parser_init();

/**
 * Dado un datagrama (array de bytes) de autentificacion para el proxy y su longitud, parsea el datagrama
 * Si no cumple con el RFC devuelve INVALID_INPUT_FORMAT_ERROR en el campo de error de la estructura.
 */
struct proxy_credentials * proxy_credentials_parser_consume(uint8_t *s, size_t length, struct proxy_credentials * ans);

/**
 * Libera la memoria utilizada por la estructura, si proxy_credentials es NULL, no hace nada
 */ 
void proxy_credentials_free(struct proxy_credentials * proxy_credentials);


#endif
