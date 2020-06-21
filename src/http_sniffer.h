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
    char * user;
    char * password;
    error_t error;
};

/**
 * Se pasa como argumento el request HTTP completo para que sea parseado.
 * Devuelve en cada campo de la estructura los campos parseados.
 * En caso de que haya algun error, se devuelve en el campo error el error correspondiente del enum "errors" 
 * y el resto de los campos en NULL.
 * 
 * Se debe hacer un free_http_credentials del puntero devuelto cuando no se use más.
 */
struct http_credentials * http_sniffer(char * s);


/**
 * Libera la memoria utilizada por la estructura, si http_credentials es NULL, no hace nada
 */ 
void free_http_credentials(struct http_credentials * http_credentials);
#endif
