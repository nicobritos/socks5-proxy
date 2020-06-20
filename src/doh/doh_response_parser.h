#ifndef HTTP_RESPONSE_PARSER_H_
#define HTTP_RESPONSE_PARSER_H_


/**
 * doh_response_parser_feed.c -- parser de respuestas HTTP.
 *
 * Permite extraer de una respuesta HTTP :
 *      1. El codigo de estado HTTP de la respuesta
 *      2. La descripciÃ³n del codigo de la respuesta
 *      3. Los bytes en la secciÃ³n del cuerpo de la respuesta (si la hubiere)
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define MAX_ADDR 6
#define IP_4_BYTES 4
#define IP_6_BYTES 16


typedef enum errors{
    INVALID_INPUT_FORMAT_ERROR,  // Si el string de entrada no estaba en algun formato vÃ¡lido de respuesta HTTP (1.1)
    REALLOC_ERROR,               // Si al hacer un realloc se produjo algun error
} http_response_parser_error_t;

typedef struct {
  uint8_t byte[IP_6_BYTES]; // en orden inverso
} ipv6_addr_t;

struct doh_response {
    uint16_t status_code;
    char * code_description;
    unsigned int ttl[MAX_ADDR]; // Time To Live (in seconds)
    int ipv4_qty; // Cantidad de ips en el array ipv4_addr
    uint32_t ipv4_addr[MAX_ADDR];
    int ipv6_qty; // Cantidad de ips en el array ipv6_addr
    ipv6_addr_t ipv6_addr[MAX_ADDR];

    /** Parser */
    struct doh_parser *_doh_parser;
};

struct doh_response *doh_response_parser_init();

/**
 * Se pasa como argumento la respuesta HTTP incompleta para que sea parseada y la longitud de dicha respuesta.
 * Devuelve en cada campo de la estructura los campos parseados.
 * En caso de que haya algun error, se devuelve en status_code el error correspondiente del enum "errors"
 * y el resto de los campos en NULL.
 *
 * Devuelve true si termino, false sino
 */
bool doh_response_parser_feed(struct doh_response *doh_response, uint8_t * s, size_t s_length);

bool doh_response_parser_is_done(struct doh_response *doh_response);

/**
 * Devuelve true si el parser termino por error, false sino
 */
bool doh_response_parser_error(struct doh_response *doh_response);

/**
 * Libera la memoria utilizada por la estructura, si doh_response es NULL, no hace nada
 */ 
void doh_response_parser_free(struct doh_response * http_response);


#endif