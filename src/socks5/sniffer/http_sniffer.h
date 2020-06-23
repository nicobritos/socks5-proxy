#ifndef HTTP_SNIFFER_PARSER_H_
#define HTTP_SNIFFER_PARSER_H_

/**
 * http_sniffer.c -- parser de request HTTP para obtener usuario y contraseña.
 *
 * Permite extraer de un request HTTP, el header Authorization y decodofica:
 *      1. El usuario
 *      2. La contraseña
 */
#include <stdint.h>
#include <stddef.h>

typedef enum errors{
    NO_ERROR,
    INVALID_INPUT_FORMAT_ERROR,  // Si el string de entrada no estaba en algun formato válido de respuesta HTTP (1.1)
    REALLOC_ERROR,               // Si al hacer un realloc se produjo algun error
    NO_COLON,                   // Si el string en base64 decodificado no tenia el ":" (separador entre user y password)
}error_t;

struct http_credentials {
    char * user; // either NULL or NULL terminated
    char * password; // either NULL or NULL terminated
    error_t error;
    uint8_t finished;
    struct parser * parser;
    size_t auth_current_length;
    char * encoded_auth;
};

struct http_credentials * http_sniffer_init();

/**
 * Se pasa como argumento el request HTTP completo para que sea parseado.
 * Devuelve en cada campo de la estructura los campos parseados.
 * En caso de que haya algun error, se devuelve en el campo error el error correspondiente del enum "errors" 
 * y el resto de los campos en NULL.
 * 
 * Se debe hacer un free_http_credentials del puntero devuelto cuando no se use más.
 */
struct http_credentials * http_sniffer_consume(uint8_t * s, size_t length, struct http_credentials * http_credentials);

void http_sniffer_destroy_parser(struct http_credentials * http_credentials);



/**
 * Libera la memoria utilizada por la estructura, si http_credentials es NULL, no hace nada
 */ 
void free_http_credentials(struct http_credentials * http_credentials);
#endif
