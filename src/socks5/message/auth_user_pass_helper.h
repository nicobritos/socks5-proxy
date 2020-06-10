#ifndef PC_2020A_6_TPE_SOCKSV5_AUTH_USER_PASS_HELPER_H
#define PC_2020A_6_TPE_SOCKSV5_AUTH_USER_PASS_HELPER_H

#include <stdint.h>
#include <stdbool.h>

#define AUTH_USER_PASS_HELPER_OK 0
#define AUTH_USER_PASS_HELPER_ERROR_NO_MEMORY 1
#define AUTH_USER_PASS_HELPER_ERROR_READING_FILE 2
#define AUTH_USER_PASS_HELPER_ERROR_FORMAT_FILE 3
#define AUTH_USER_PASS_HELPER_ERROR_WRITING_FILE 4
#define AUTH_USER_PASS_HELPER_ERROR_USER_NOT_FOUND 5
#define AUTH_USER_PASS_HELPER_ERROR_INVALID_CREDENTIALS 6
#define AUTH_USER_PASS_HELPER_ERROR_ALREADY_INITIALIZED 7
#define AUTH_USER_PASS_HELPER_ERROR_NOT_INITIALIZED 8
#define AUTH_USER_PASS_HELPER_ERROR_USER_ALREADY_EXISTS 9

#define AUTH_USER_PASS_DEFAULT_USER "root"
#define AUTH_USER_PASS_DEFAULT_USER_LENGTH 4
#define AUTH_USER_PASS_DEFAULT_PASS "root"

struct auth_user_pass_credentials {
    const char *username;
    const char *password;
    /** Guardamos el largo del username para evitar volver a recorrerlo */
    uint8_t username_length;
};

/**
 * Inicializa y pone los user/pass en memoria
 * @return AUTH_USER_PASS_HELPER_... acorde al resultado
 */
uint8_t auth_user_pass_helper_init();

/**
 * Agrega un usuario y contrasena y lo guarda en el archivo
 * @param credentials
 * @return AUTH_USER_PASS_HELPER_... acorde al resultado
 */
uint8_t auth_user_pass_helper_add(const struct auth_user_pass_credentials *credentials);

/**
 * Remueve las credenciales asociadas a un usuario y lo guarda en el archivo
 * @param username del usuario al cual sacar
 * @return AUTH_USER_PASS_HELPER_... acorde al resultado
 */
uint8_t auth_user_pass_helper_remove(const char *username);

/**
 * Verifica que el usuario exista y que la contrasena sea correcta
 * @param credentials
 * @return bool
 */
bool auth_user_pass_helper_verify(const struct auth_user_pass_credentials *credentials);

/**
 * Elimina toda la informacion de memoria
 */
void auth_user_pass_helper_close();

#endif //PC_2020A_6_TPE_SOCKSV5_AUTH_USER_PASS_HELPER_H
