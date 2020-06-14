/**
 * Este archivo se encarga de mantener los usuarios en memoria,
 * verificar credenciales, guardarlas en disco y eliminarlas.
 * NO maneja concurrencia por el momento
 */

#include "auth_user_pass_helper.h"
#include "../../utils/sorted_hashmap.h"
#include <string.h>

// TODO: Manejar concurrencia

#define INITIAL_HASHMAP_SIZE 50
#define INITIAL_HASH_VALUE 5381u
#define SHIFT_HASH_VALUE 5u

/** ------------- DECLARATIONS ------------- */
/**
 * Esta funcion hashea un credentials (se hashea solo el username)
 * @param e
 * @return
 */
static hash_t auth_user_pass_hasher(void *e);
/**
 * Esta funcion compara un credentials (se compara solo el username)
 * @param e1
 * @param e2
 * @return
 */
static int8_t auth_user_pass_cmp(void *e1, void *e2);

static sorted_hashmap_t credentials_map = NULL;

static struct auth_user_pass_credentials default_user = {
        .username = AUTH_USER_PASS_DEFAULT_USER,
        .username_length = AUTH_USER_PASS_DEFAULT_USER_LENGTH,
        .password = AUTH_USER_PASS_DEFAULT_PASS
};

/**
 * Inicializa y pone los user/pass en memoria
 * @return auth_user_pass_helper_status_... acorde al resultado
 */
enum auth_user_pass_helper_status auth_user_pass_helper_init() {
    if (credentials_map != NULL) return auth_user_pass_helper_status_error_already_initialized;
    credentials_map = sorted_hashmap_create(INITIAL_HASHMAP_SIZE);
    if (credentials_map == NULL) return auth_user_pass_helper_status_error_no_memory;

    sorted_hashmap_set_hasher(credentials_map, auth_user_pass_hasher);
    sorted_hashmap_set_cmp(credentials_map, auth_user_pass_cmp);

    /** Agregamos el default user */
    sorted_hashmap_node node = sorted_hashmap_add(credentials_map, (void*)&default_user);
    if (node == NULL) return auth_user_pass_helper_status_error_no_memory;

    // TODO: read from file
    return auth_user_pass_helper_status_ok;
}

/**
 * Agrega un usuario y contrasena y lo guarda en el archivo
 * @param credentials
 * @return auth_user_pass_helper_status_... acorde al resultado
 */
enum auth_user_pass_helper_status auth_user_pass_helper_add(const struct auth_user_pass_credentials *credentials) {
    if (credentials_map == NULL) return auth_user_pass_helper_status_error_not_initialized;
    if (credentials == NULL) return auth_user_pass_helper_status_error_invalid_credentials;

    sorted_hashmap_node node = sorted_hashmap_find(credentials_map, (void*)credentials);
    if (node != NULL) {
        struct auth_user_pass_credentials *node_credentials = sorted_hashmap_get_element(node);
        if (strcmp(node_credentials->username, credentials->username) != 0)
            return auth_user_pass_helper_status_error_user_already_exists;

        node_credentials->password = credentials->password;
    } else {
        sorted_hashmap_add(credentials_map, (void*)credentials);
    }
    return auth_user_pass_helper_status_ok;
}

/**
 * Remueve las credenciales asociadas a un usuario y lo guarda en el archivo
 * @param username del usuario al cual sacar
 * @return auth_user_pass_helper_status_... acorde al resultado
 */
enum auth_user_pass_helper_status auth_user_pass_helper_remove(const char *username) {
    if (credentials_map == NULL) return auth_user_pass_helper_status_error_not_initialized;
    if (username == NULL || *username == '\0') return auth_user_pass_helper_status_error_invalid_credentials;

    struct auth_user_pass_credentials credentials = {
            .username = username,
            .username_length = strlen(username),
            .password = NULL
    };
    sorted_hashmap_node node = sorted_hashmap_find(credentials_map, (void*) &credentials);
    if (node == NULL)
        return auth_user_pass_helper_status_error_user_not_found;

    sorted_hashmap_remove(credentials_map, node);
    return auth_user_pass_helper_status_ok;
}

/**
 * Verifica que el usuario exista y que la contrasena sea correcta
 * @param credentials
 * @return bool
 */
bool auth_user_pass_helper_verify(const struct auth_user_pass_credentials *credentials) {
    if (credentials == NULL
        || credentials_map == NULL
        || sorted_hashmap_get_total_nodes(credentials_map) == 0
        ) return false;

    sorted_hashmap_node node = sorted_hashmap_find(credentials_map, (void*) credentials);
    if (node == NULL) return false;
    const struct auth_user_pass_credentials *other_credentials = sorted_hashmap_get_element(node);
    return strcmp(credentials->password, other_credentials->password) == 0;
}

/**
 * Elimina toda la informacion de memoria
 */
void auth_user_pass_helper_close() {
    if (credentials_map == NULL) return;
    sorted_hashmap_free(credentials_map);
    credentials_map = NULL;
}

/** ---------------- PRIVATE ----------------- */
/**
 * Esta funcion hashea un credentials (se hashea solo el username)
 * @param e
 * @return
 */
static hash_t auth_user_pass_hasher(void *e) {
    struct auth_user_pass_credentials *credentials = e;

    /** See https://stackoverflow.com/a/7666577 */
    hash_t hash = INITIAL_HASH_VALUE;
    uint8_t c;
    const char *username = credentials->username;
    while ((c = *username++)) hash = ((hash << SHIFT_HASH_VALUE) + hash) + c; /* hash * 33 + c */

    return hash;
}

/**
 * Esta funcion compara un credentials (se compara solo el username)
 * @param e1
 * @param e2
 * @return
 */
static int8_t auth_user_pass_cmp(void *e1, void *e2) {
    struct auth_user_pass_credentials *credentials1 = e1;
    struct auth_user_pass_credentials *credentials2 = e2;

    if (credentials1->username_length < credentials2->username_length)
        return -1;
    if (credentials1->username_length > credentials2->username_length)
        return 1;
    return strcmp(credentials1->username, credentials2->username);
}
