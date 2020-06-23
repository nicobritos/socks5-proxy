#ifndef POP3_SNIFFER_H_
#define POP3_SNIFFER_H_

/**
 * pop3_sniffer.c -- parser de pop3 para obtener usuario y contraseña.
 *
 * Permite extraer de una conversacion POP3 :
 *      1. El usuario y la longitud de ese string
 *      2. La contraseña y la longitud de ese string
 */
#include <stdint.h>
#include <stddef.h>

typedef enum errors{
    NO_ERROR = 0,
    REALLOC_ERROR,               // Si al hacer un realloc se produjo algun error
}error_t;

struct pop3_credentials {
    uint8_t finished;
    char * user;
    char * password;
    size_t user_length;
    size_t password_length;
    error_t error;
};

/** Crea una estructura inicializada para la primera llamada de pop3_sniffer_consume **/
struct pop3_credentials * pop3_credentials_init();

/** Inicializa el parser **/
struct parser * pop3_sniffer_init();

/**
 * Se pasa como argumento la conversacion POP3 parcial para que sea parseada, el parser y
 * el pop3_credentials de la llamada anterior a esta funcion o si es la primera vez que se
 * la llama, el devuelto por pop3_credentials_init
 * 
 * Devuelve en cada campo de la estructura los campos parseados.
 * 
 * El parser cambia su estado cada vez que se llama a esta funcion correspondiendo con la
 * conversacion pasada por argumento
 * 
 * Si surge algun error durante el parseo se retorna en el campo error
 * 
 * Si la conversacion no tenia las credenciales completamente el campo finished
 * se setea en 0. Otro numero en caso contrario.
 * 
 * Se debe hacer un free_pop3_credentials del puntero devuelto cuando no se use más.
 */
struct pop3_credentials * pop3_sniffer_consume(struct parser * parser, struct pop3_credentials * pop3_credentials, char * s);

/** Destruye el parser **/
void pop3_sniffer_destroy(struct parser * parser);

/**
 * Libera la memoria utilizada por la estructura, si pop3_credentials es NULL, no hace nada
 */ 
void free_pop3_credentials(struct pop3_credentials * pop3_credentials);


#endif
