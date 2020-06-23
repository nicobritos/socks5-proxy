/**
 * Este archivo se encarga de mantener los usuarios en memoria,
 * verificar credenciales, guardarlas en disco y eliminarlas.
 * NO maneja concurrencia por el momento
 */

#include "auth_user_pass_helper.h"
#include <string.h>

#define INITIAL_HASHMAP_SIZE 50

/** ------------- DECLARATIONS ------------- */
static struct auth_user_pass_credentials *duplicate_credentials(const struct auth_user_pass_credentials *credentials);

/**
 * Esta funcion hashea un credentials (se hashea solo el username)
 * @param e
 * @return
 */
static hash_t auth_user_pass_hasher(void *e);

/**
 * Esta funcion hace un free de un credentials cuando se elimina del mapa
 * @param e
 * @return
 */
static void auth_user_pass_freer(void *e);

/**
 * Esta funcion compara un credentials (se compara solo el username)
 * @param e1
 * @param e2
 * @return
 */
static int8_t auth_user_pass_cmp(void *e1, void *e2);

static sorted_hashmap_t credentials_map = NULL;

/**
 * Inicializa y pone los user/pass en memoria
 * @return auth_user_pass_helper_status_... acorde al resultado
 */
enum auth_user_pass_helper_status auth_user_pass_helper_init() {
    if (credentials_map != NULL) return auth_user_pass_helper_status_error_already_initialized;
    credentials_map = sorted_hashmap_create(INITIAL_HASHMAP_SIZE);
    if (credentials_map == NULL) return auth_user_pass_helper_status_error_no_memory;

    sorted_hashmap_set_hasher(credentials_map, auth_user_pass_hasher);
    sorted_hashmap_set_freer(credentials_map, auth_user_pass_freer);
    sorted_hashmap_set_cmp(credentials_map, auth_user_pass_cmp);

    /** Agregamos el default user */
    struct auth_user_pass_credentials default_user = {
            .username = AUTH_USER_PASS_DEFAULT_USER,
            .username_length = AUTH_USER_PASS_DEFAULT_USER_LENGTH,
            .password = AUTH_USER_PASS_DEFAULT_PASS,
            .active = true
    };

    struct auth_user_pass_credentials *user = duplicate_credentials(&default_user);
    if (user == NULL) {
        sorted_hashmap_free(credentials_map);
        credentials_map = NULL;
        return auth_user_pass_helper_status_error_no_memory;
    }

    sorted_hashmap_node node = sorted_hashmap_add(credentials_map, (void*)user);
    if (node == NULL) {
        free(user);
        sorted_hashmap_free(credentials_map);
        credentials_map = NULL;
        return auth_user_pass_helper_status_error_no_memory;
    }

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
        return auth_user_pass_helper_status_error_user_already_exists;
    } else {
        sorted_hashmap_add(credentials_map, (void*)credentials);
    }
    return auth_user_pass_helper_status_ok;
}

/**
 * Activa o desactiva un usuario. Deberia de ser solo usable desde el monitor
 */
enum auth_user_pass_helper_status auth_user_pass_helper_set_enable(const char *username, bool enable) {
    if (credentials_map == NULL) return auth_user_pass_helper_status_error_not_initialized;
    if (username == NULL) return auth_user_pass_helper_status_error_invalid_credentials;

    struct auth_user_pass_credentials credentials = {
            .username = (char *) username, // No nos importa que no sea const porque solo lo usamos en busqueda
            .username_length = strlen(username),
    };
    sorted_hashmap_node node = sorted_hashmap_find(credentials_map, (void*)&credentials);
    if (node == NULL) return auth_user_pass_helper_status_error_user_not_found;

    ((struct auth_user_pass_credentials *) sorted_hashmap_get_element(node))->active = enable;

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
            .username = (char *)username,
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
    return other_credentials->active && strcmp(credentials->password, other_credentials->password) == 0;
}

/**
 * Elimina toda la informacion de memoria
 */
void auth_user_pass_helper_close() {
    if (credentials_map == NULL) return;
    sorted_hashmap_free(credentials_map);
    credentials_map = NULL;
}

/**
 * Crea una lista con todos los nodos
 */
sorted_hashmap_list_t auth_user_pass_get_values() {
    return sorted_hashmap_get_values(credentials_map);
}

/** ---------------- PRIVATE ----------------- */
static struct auth_user_pass_credentials *duplicate_credentials(const struct auth_user_pass_credentials *credentials) {
    struct auth_user_pass_credentials *copy = malloc(sizeof(*copy));
    if (copy == NULL) return NULL;

    copy->username_length = strlen(credentials->username);
    size_t password_length = strlen(credentials->password);

    copy->username = malloc(sizeof(*copy->username) * (copy->username_length + 1));
    if (copy->username == NULL) {
        free(copy);
        return NULL;
    }
    memcpy(copy->username, credentials->username, credentials->username_length + 1);

    copy->password = malloc(sizeof(*copy->password) * password_length + 1);
    if (copy->password == NULL) {
        free(copy->username);
        free(copy);
        return NULL;
    }
    memcpy(copy->password, credentials->password, password_length + 1);

    copy->active = credentials->active;

    return copy;
}

/**
 * Esta funcion hashea un credentials (se hashea solo el username)
 * @param e
 * @return
 */
static hash_t auth_user_pass_hasher(void *e) {
    struct auth_user_pass_credentials *credentials = e;

    /** See https://stackoverflow.com/a/7666577 */
    hash_t hash = GENERIC_INITIAL_HASH_VALUE;
    uint8_t c;
    const char *username = credentials->username;
    while ((c = *username++)) hash = ((hash << GENERIC_SHIFT_HASH_VALUE) + hash) + c; /* hash * 33 + c */

    return hash;
}

/**
 * Esta funcion hace un free de un credentials cuando se elimina del mapa
 * @param e
 * @return
 */
static void auth_user_pass_freer(void *e) {
    struct auth_user_pass_credentials *credentials = e;

    free(credentials->username);
    free(credentials->password);
    free(e);
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
