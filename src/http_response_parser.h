#ifndef HTTP_RESPONSE_PARSER_H_
#define HTTP_RESPONSE_PARSER_H_

/**
 * http_response_parser.c -- parser de respuestas HTTP.
 *
 * Permite extraer de una respuesta HTTP :
 *      1. El codigo de estado HTTP de la respuesta
 *      2. La descripción del codigo de la respuesta
 *      3. Los bytes en la sección del cuerpo de la respuesta (si la hubiere)
 */
#include <stdint.h>
#include <stddef.h>

typedef enum errors{
    INVALID_INPUT_FORMAT_ERROR,  // Si el string de entrada no estaba en algun formato válido de respuesta HTTP (1.1)
    REALLOC_ERROR,               // Si al hacer un realloc se produjo algun error
}error_t;

struct http_response {
    uint16_t status_code;
    char * code_description;
    uint8_t * data;
};

/**
 * Se pasa como argumento la respuesta HTTP completa para que sea parseada.
 * Devuelve en cada campo de la estructura los campos parseados.
 * En caso de que haya algun error, se devuelve en status_code el error correspondiente del enum "errors" 
 * y el resto de los campos en NULL.
 * 
 * Se debe hacer un free_http_response del puntero devuelto cuando no se use más.
 */
struct http_response * http_response_parser(char * s);


/**
 * Libera la memoria utilizada por la estructura, si http_response es NULL, no hace nada
 */ 
void free_http_response(struct http_response * http_response);


#endif