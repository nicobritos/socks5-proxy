/**
 * Parser de metodo de autenticacion por Username/Password [RFC1929]
 */
#include <stdio.h>
#include <stdlib.h>

#include "auth_user_pass_parser.h"

#define VALID_VERSION 0x01

/** inicializa el parser */
void auth_user_pass_parser_init(struct auth_user_pass_parser *p) {
    if (p == NULL) return;
    p->_username = p->_password = NULL;
    p->_username_length = p->_username_index = 0;
    p->_password_length = p->_password_index = 0;
    p->_state = auth_user_pass_ver;
}

/** entrega un byte al parser. retorna el nuevo estado del parser, o el mismo si no hubo cambios */
enum auth_user_pass_state auth_user_pass_parser_feed(struct auth_user_pass_parser *p, uint8_t b) {
    switch (p->_state) {
        case auth_user_pass_ver:
            p->_state = b == VALID_VERSION ? p->_state = auth_user_pass_user_len : auth_user_pass_error_invalid_version;
            break;
        case auth_user_pass_user_len:
            if (b != 0) {
                if ((p->_username = malloc(b + 1)) == NULL) {
                    p->_state = auth_user_pass_error_no_memory;
                } else {
                    p->_username_index = 0;
                    p->_username_length = b;

                    p->_state = auth_user_pass_user;
                }
            } else {
                p->_state = auth_user_pass_error_invalid_params;
            }
            break;
        case auth_user_pass_user:
            p->_username[p->_username_index++] = b;
            if (p->_username_index == p->_username_length) {
                p->_username[p->_username_index + 1] = '\0';
                p->_state = auth_user_pass_pass_len;
            }
            break;
        case auth_user_pass_pass_len:
            if (b != 0) {
                if ((p->_password = malloc(b + 1)) == NULL) {
                    p->_state = auth_user_pass_error_no_memory;
                } else {
                    p->_password_index = 0;
                    p->_password_length = b;

                    p->_state = auth_user_pass_pass;
                }
            } else {
                p->_state = auth_user_pass_error_invalid_params;
            }
            break;
        case auth_user_pass_pass:
            p->_password[p->_password_index++] = b;
            if (p->_password_index == p->_password_length) {
                p->_username[p->_password_index + 1] = '\0';
                p->_state = auth_user_pass_ok;
            }
            break;
        case auth_user_pass_ok:
        case auth_user_pass_error_no_memory:
        case auth_user_pass_error_invalid_params:
        case auth_user_pass_error_invalid_version:
            break;
        default:
            fprintf(stderr, "unknown auth_user_pass state %d\n", p->_state);
            abort();
    }

    return p->_state;
}

/**
 * por cada elemento del buffer llama a `auth_user_pass_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum auth_user_pass_state auth_user_pass_parser_consume(buffer *b, struct auth_user_pass_parser *p, bool *errored) {
    enum auth_user_pass_state st = p->_state;

    while (!auth_user_pass_parser_is_done(st, errored) && buffer_can_read(b)) {
        st = auth_user_pass_parser_feed(p, buffer_read(b));
    }
    return st;
}

/**
 * Permite distinguir a quien usa auth_user_pass_parser_feed si debe seguir
 * enviando caracters o no.
 *
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool auth_user_pass_parser_is_done(enum auth_user_pass_state state, bool *errored) {
    if (state == auth_user_pass_ok)
        return true;
    if (state == auth_user_pass_error_invalid_version
        || state == auth_user_pass_error_invalid_params
        || state == auth_user_pass_error_no_memory) {
        if (errored != NULL)
            *errored = true;
        return true;
    }
    return false;
}

/**
 * Setea las credenciales
 * @param parser el parser que contiene los datos
 * @param credentials el struct donde guardara las credenciales
 * @return true si se guardaron, false sino
 */
bool auth_user_pass_parser_set_credentials(const struct auth_user_pass_parser *parser, struct auth_user_pass_credentials *credentials) {
    if (!auth_user_pass_parser_is_done(parser->_state, NULL))
        return false;

    credentials->username = parser->_username;
    credentials->username_length = parser->_username_length;
    credentials->password = parser->_password;
    return true;
}

/**
 * En caso de que se haya llegado a un estado de error, permite obtener una
 * representación textual que describe el problema
 */
const char *auth_user_pass_parser_error(const struct auth_user_pass_parser *p) {
    switch (p->_state) {
        case auth_user_pass_error_no_memory:
            return "no memory available";
        case auth_user_pass_error_invalid_params:
            return "invalid parameters";
        case auth_user_pass_error_invalid_version:
            return "invalid version number";
        default:
            return "";
    }
}

/** libera recursos internos del parser */
void auth_user_pass_parser_close(struct auth_user_pass_parser *p) {
    if (p->_username != NULL) {
        free(p->_username);
        p->_username = NULL;
        p->_username_length = p->_username_index = 0 ;
    }
    if (p->_password != NULL) {
        free(p->_password);
        p->_password = NULL;
        p->_password_length = p->_password_index = 0;
    }
}
