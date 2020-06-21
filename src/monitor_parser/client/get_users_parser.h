#ifndef GET_USERS_PARSER_H_
#define GET_USERS_PARSER_H_


/**
 * get_users_parser.c -- parser de la respuesta del comando GET USERS (ver RFC).
 *
 * Permite extraer:
 *      1. La cantidad de usuarios
 *      2. La cantidad de conexiones actuales
 *      3. La cantidad total de bytes transferidos
 */
#include <stdint.h>
#include <stddef.h>

typedef enum errors{
    NO_ERROR,
    INVALID_INPUT_FORMAT_ERROR,  // Si el datagrama no cumple el formato del RFC
    REALLOC_ERROR,               // Si al hacer un realloc se produjo algun error
}get_users_parser_error_t;

struct user {
    char * user;
    uint8_t status;
};

struct users {
    struct user * users;
    size_t users_qty;
    get_users_parser_error_t error;
};

/**
 * Dado un datagrama (array de bytes) de respuesta del comando GET USERS (ver RFC) para el proxy
 * y su longitud, parsea el datagrama.
 * Si no cumple con el RFC devuelve INVALID_INPUT_FORMAT_ERROR en el campo de error de la estructura.
 */
struct users * get_users_parser(uint8_t *s, size_t length);

/**
 * Libera la memoria utilizada por la estructura, si metrics es NULL, no hace nada
 */ 
void free_users(struct users * users);


#endif
