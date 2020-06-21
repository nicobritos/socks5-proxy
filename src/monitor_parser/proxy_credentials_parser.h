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

typedef enum errors{
    NO_ERROR,
    INVALID_INPUT_FORMAT_ERROR,  // Si el datagrama no cumple el formato del RFC
    REALLOC_ERROR,               // Si al hacer un realloc se produjo algun error
}proxy_credentials_parser_error_t;

struct proxy_credentials {
    uint8_t version;
    char * username;
    char * password;
    proxy_credentials_parser_error_t error;
};

struct proxy_credentials * proxy_credentials_parser(uint8_t *s, size_t length);

/**
 * Libera la memoria utilizada por la estructura, si proxy_credentials es NULL, no hace nada
 */ 
void proxy_credentials_free(struct proxy_credentials * proxy_credentials);


#endif
