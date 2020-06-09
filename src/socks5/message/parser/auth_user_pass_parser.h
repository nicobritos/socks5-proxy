#ifndef PC_2020A_6_TPE_SOCKSV5_AUTH_USER_PASS_PARSER_H
#define PC_2020A_6_TPE_SOCKSV5_AUTH_USER_PASS_PARSER_H

#include <stdint.h>
#include <stdbool.h>

#include "../../../buffer.h"
#include "../auth_user_pass_helper.h"

#define AUTH_USER_PASS_DEFAULT_USER "root"
#define AUTH_USER_PASS_DEFAULT_USER_LENGTH 4
#define AUTH_USER_PASS_DEFAULT_PASS "root"
#define AUTH_USER_PASS_DEFAULT_PASS_LENGTH 4

/**
 * Once the SOCKS V5 server has started, and the client has selected the
 * Username/Password Authentication protocol, the Username/Password
 * subnegotiation begins.  This begins with the client producing a
 * Username/Password request:
 *
 *         +----+------+----------+------+----------+
 *         |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 *         +----+------+----------+------+----------+
 *         | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
 *         +----+------+----------+------+----------+
 *
 * The VER field contains the current version of the subnegotiation,
 * which is X'01'. The ULEN field contains the length of the UNAME field
 8 that follows. The UNAME field contains the username as known to the
 * source operating system. The PLEN field contains the length of the
 * PASSWD field that follows. The PASSWD field contains the password
 * association with the given UNAME.
 */

/** estado del parser */
enum auth_user_pass_state {
    /** En este estado leeremos la version */
    auth_user_pass_ver,
    /** En este estado leeremos el length del username */
    auth_user_pass_user_len,
    /** En este estado leeremos el username */
    auth_user_pass_user,
    /** En este estado leeremos el password */
    auth_user_pass_pass,
    /** En este estado leeremos el length del password */
    auth_user_pass_pass_len,

    /** Estados terminales */
    auth_user_pass_ok,
    auth_user_pass_error_invalid_params,
    auth_user_pass_error_invalid_version,
    auth_user_pass_error_no_memory
};

struct auth_user_pass_parser {
    enum auth_user_pass_state _state;
    char *_username;
    char *_password;
    uint8_t _username_length;
    uint8_t _password_length;
    uint8_t _username_index;
    uint8_t _password_index;
};

/** inicializa el parser */
void auth_user_pass_parser_init(struct auth_user_pass_parser *p);

/** entrega un byte al parser. retorna el nuevo estado del parser, o el mismo si no hubo cambios */
enum auth_user_pass_state auth_user_pass_parser_feed(struct auth_user_pass_parser *p, uint8_t b);

/**
 * por cada elemento del buffer llama a `auth_user_pass_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum auth_user_pass_state auth_user_pass_parser_consume(buffer *b, struct auth_user_pass_parser *p, bool *errored);

/**
 * Permite distinguir a quien usa auth_user_pass_parser_feed si debe seguir
 * enviando caracters o no.
 *
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool auth_user_pass_parser_is_done(enum auth_user_pass_state state, bool *errored);

/**
 * Setea las credenciales
 * @param parser el parser que contiene los datos
 * @param credentials el struct donde guardara las credenciales
 * @return true si se guardaron, false sino
 */
bool auth_user_pass_parser_set_credentials(const struct auth_user_pass_parser *parser, struct auth_user_pass_credentials *credentials);

/**
 * En caso de que se haya llegado a un estado de error, permite obtener una
 * representación textual que describe el problema
 */
const char *auth_user_pass_parser_error(const struct auth_user_pass_parser *p);

/** libera recursos internos del parser */
void auth_user_pass_parser_close(struct auth_user_pass_parser *p);

#endif //PC_2020A_6_TPE_SOCKSV5_AUTH_USER_PASS_PARSER_H
