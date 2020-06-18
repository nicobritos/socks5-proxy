#ifndef HTTP_RESPONSE_PARSER_H_
#define HTTP_RESPONSE_PARSER_H_


/**
 * http_response_parser.c -- parser de respuestas HTTP.
 *
 * Permite extraer de una respuesta HTTP :
 *      1. El codigo de estado HTTP de la respuesta
 *      2. La descripciÃ³n del codigo de la respuesta
 *      3. Los bytes en la secciÃ³n del cuerpo de la respuesta (si la hubiere)
 */
#include <stdint.h>
#include <stddef.h>

#define MAX_ADDR 6
#define IP_4_BYTES 4
#define IP_6_BYTES 16


typedef enum errors{
    INVALID_INPUT_FORMAT_ERROR,  // Si el string de entrada no estaba en algun formato vÃ¡lido de respuesta HTTP (1.1)
    REALLOC_ERROR,               // Si al hacer un realloc se produjo algun error
}error_t;

typedef struct {
  uint8_t byte[IP_6_BYTES]; // en orden inverso
} ipv6_addr_t;

typedef struct {
  uint8_t byte[IP_4_BYTES]; // en orden inverso
} ipv4_addr_t;


struct http_response {
    uint16_t status_code;
    char * code_description;
    unsigned int ttl[MAX_ADDR]; // Time To Live (in seconds)
    int ipv4_qty; // Cantidad de ips en el array ipv4_addr
    ipv4_addr_t ipv4_addr[MAX_ADDR];
    int ipv6_qty; // Cantidad de ips en el array ipv6_addr
    ipv6_addr_t ipv6_addr[MAX_ADDR];
};

/**
 * Se pasa como argumento la respuesta HTTP completa para que sea parseada y la longitud de dicha respuesta. 
 * Devuelve en cada campo de la estructura los campos parseados.
 * En caso de que haya algun error, se devuelve en status_code el error correspondiente del enum "errors" 
 * y el resto de los campos en NULL.
 * 
 * Se debe hacer un free_http_response del puntero devuelto cuando no se use mÃ¡s.
 */
struct http_response * http_response_parser(uint8_t * bytes, size_t bytes_qty);


/**
 * Libera la memoria utilizada por la estructura, si http_response es NULL, no hace nada
 */ 
void free_http_response(struct http_response * http_response);


#endif