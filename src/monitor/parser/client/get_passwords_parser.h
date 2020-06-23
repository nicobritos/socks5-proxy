#ifndef GET_ACCESS_PARSER_H_
#define GET_ACCESS_PARSER_H_


/**
 * get_passwords_parser.c -- parser de la respuesta del comando GET PASSWORDS (ver RFC).
 *
 * Permite extraer:
 *      1. Las entradas del log. Cada entrada contiene:
 *          a. El timestamp del acceso (Formato ISO-8601)
 *          b. El usuario (nombre y status)
 *          c. El IP de origen
 *          d. El puerto de origen
 *          e. El nombre del destino
 *          f. El puerto de destino
 */
#include <stdint.h>
#include <stddef.h>
#include "../parser_errors.h"

typedef struct {
    char * time;
    char * user;
    char * protocol;
    char * destination;
    uint32_t destination_port;
    char * username;
    char * password;
} password_entry;

struct passwords {
    password_entry * entries;
    size_t entry_qty;
    parser_error_t error;
};

/**
 * Dado un datagrama (array de bytes) de respuesta del comando GET ACCESS LOG (ver RFC) para el proxy
 * y su longitud, parsea el datagrama.
 * Si no cumple con el RFC devuelve INVALID_INPUT_FORMAT_ERROR en el campo de error de la estructura.
 */
struct passwords * get_passwords_parser(uint8_t *s, size_t length);

/**
 * Libera la memoria utilizada por la estructura, si metrics es NULL, no hace nada
 */ 
void free_passwords(struct passwords * users);


#endif
