#ifndef PC_2020A_6_TPE_SOCKSV5_AUTH_USER_PASS_HELPER_H
#define PC_2020A_6_TPE_SOCKSV5_AUTH_USER_PASS_HELPER_H

#include <stdint.h>
#include <stdbool.h>

#define AUTH_USER_PASS_DEFAULT_USER "root"
#define AUTH_USER_PASS_DEFAULT_USER_LENGTH 4
#define AUTH_USER_PASS_DEFAULT_PASS "root"

enum auth_user_pass_helper_status {
    auth_user_pass_helper_status_ok,
    auth_user_pass_helper_status_error_no_memory,
    auth_user_pass_helper_status_error_user_not_found,
    auth_user_pass_helper_status_error_invalid_credentials,
    auth_user_pass_helper_status_error_already_initialized,
    auth_user_pass_helper_status_error_not_initialized,
    auth_user_pass_helper_status_error_user_already_exists,
};

struct auth_user_pass_credentials {
    char *username;
    char *password;
    /** Guardamos el largo del username para evitar volver a recorrerlo */
    uint8_t username_length;
    bool active;
};

/**
 * Inicializa y pone los user/pass en memoria
 * @return auth_user_pass_helper_status_... acorde al resultado
 */
enum auth_user_pass_helper_status auth_user_pass_helper_init();

/**
 * Agrega un usuario y contrasena y lo guarda en el archivo
 * @param credentials
 * @return auth_user_pass_helper_status_... acorde al resultado
 */
enum auth_user_pass_helper_status auth_user_pass_helper_add(const struct auth_user_pass_credentials *credentials);

/**
 * Remueve las credenciales asociadas a un usuario y lo guarda en el archivo
 * @param username del usuario al cual sacar
 * @return auth_user_pass_helper_status_... acorde al resultado
 */
enum auth_user_pass_helper_status auth_user_pass_helper_remove(const char *username);

/**
 * Activa o desactiva un usuario. Deberia de ser solo usable desde el monitor
 */
enum auth_user_pass_helper_status auth_user_pass_helper_set_enable(const char *username, bool enable);

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
