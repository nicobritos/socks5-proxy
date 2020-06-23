#ifndef GET_METRICS_PARSER_H_
#define GET_METRICS_PARSER_H_


/**
 * get_metrics_parser.c -- parser de la respuesta del comando GET METRICS (ver RFC).
 *
 * Permite extraer:
 *      1. La cantidad total de conexiones establecidas
 *      2. La cantidad de conexiones actuales
 *      3. La cantidad total de bytes transferidos
 */
#include <stdint.h>
#include <stddef.h>
#include "../parser_errors.h"

struct metrics {
    uint64_t established_cons;
    uint64_t actual_cons;
    uint64_t bytes_transferred;
    parser_error_t error;
};

/**
 * Dado un datagrama (array de bytes) de respuesta del comando GET METRICS (ver RFC) para el proxy
 * y su longitud, parsea el datagrama.
 * Si no cumple con el RFC devuelve INVALID_INPUT_FORMAT_ERROR en el campo de error de la estructura.
 */
struct metrics * get_metrics_parser(uint8_t *s, size_t length);

/**
 * Libera la memoria utilizada por la estructura, si metrics es NULL, no hace nada
 */ 
void free_metrics(struct metrics * metrics);


#endif
