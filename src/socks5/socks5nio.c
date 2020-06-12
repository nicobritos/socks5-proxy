/**
 * socks5nio.c  - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 */
#include <stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <unistd.h>  // close
#include <pthread.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#include "message/parser/hello_parser.h"
#include "message/parser/auth_user_pass_parser.h"
#include "message/parser/request_parser.h"

#include "../utils/stm.h"
#include "socks5nio.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
/** obtiene el struct (socks5 *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

/** maquina de estados general */
enum socks_v5state {
    /**
     * recibe el mensaje `parser` del cliente, y lo procesa
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - HELLO_READ  mientras el mensaje no esté completo
     *   - HELLO_WRITE cuando está completo
     *   - ERROR       ante cualquier error (IO/parseo)
     */
    HELLO_READ,

    /**
     * envía la respuesta del `parser' al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras queden bytes por enviar
     *   - REQUEST_READ cuando se enviaron todos los bytes y no se necesita autenticacion
     *   - AUTH_USER_PASS_READ cuando se enviaron todos los bytes y se necesita autenticacion
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    HELLO_WRITE,

    /**
     * Lee la informacion de autenticacion del cliente.
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - AUTH_USER_PASS_READ  mientras queden bytes por leer
     *   - AUTH_USER_PASS_WRITE cuando se leyeron todos los bytes
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    AUTH_USER_PASS_READ,

    /**
     * Envia respuesta de la informacion de autenticacion del cliente.
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - AUTH_USER_PASS_WRITE  mientras queden bytes por escribir
     *   - REQUEST_READ cuando se mando el mensaje
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    AUTH_USER_PASS_WRITE,

    /**
     * recibe el mensaje 'request' del cliente y lo inicia su proceso.
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - REQUEST_READ     mientras el mensaje no este completo
     *   - REQUEST_RESOLVE  si requiere resolver un nombre DNS
     *   - REQUEST_CONNECTING si no requiere resolver DNS
     *   - REQUEST_WRITE  si determinamos que no se puede procesar
     *   - ERROR
     */
    REQUEST_READ,

    /**
     * Aqui esperamos la resoluicion DNS
     * Intereses:
     *   - OP_NOOP sobre el client_fd. Espera un evento que la tarea bloqueante termino
     * Transiciones:
     *   - REQUEST_CONNECTING si se pudo resolver
     *   - REQUEST_WRITE sino
     */
    REQUEST_RESOLVE,

    /**
     * Espera a que se establezca la conexion al servidor
     * Intereses:
     *   - OP_WRITE sobre client_fd
     * Transiciones:
     *   - REQUEST_WRITE
     */
    REQUEST_CONNECTING,

    /**
     * Envia la respuesta del request al cliente
     * Intereses:
     *   - OP_WRITE sobre client_fd
     *   - OP_NOOP sobre server_fd
     * Transiciones:
     *   - REQUEST_WRITE mientras queden bytes por enviar
     *   - COPY si el req fue exitoso y tenemos que copiar el contenido
     *   - ERROR
     */
    REQUEST_WRITE,

    /**
     * Copia bytes entre client_fd y server_fd
     * Intereses:
     *   - OP_READ si hay espacio
     *   - OP_WRITE si hay para leer en el buffer
     * Transiciones:
     *   - DONE
     */
    COPY,

    // estados terminales
    DONE,
    ERROR,
};

/** usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
    /** buffer utilizado para I/O */
    buffer *read_buffer, *write_buffer;
    struct hello_parser parser;

    /** el método de autenticación seleccionado */
    uint8_t method;
};

/** usado por AUTH_USER_PASS_READ, AUTH_USER_PASS_WRITE */
struct auth_user_pass_st {
    /** buffer utilizado para I/O */
    buffer *read_buffer, *write_buffer;

    struct auth_user_pass_parser parser;
    struct auth_user_pass_credentials credentials;
};

struct request_st {
    buffer *read_buffer;
    buffer *write_buffer;

    /** aqui guardamos la info de la request (address, port, cmd) */
    struct request request;
    /** parser */
    struct request_parser parser;

    /** status, campo de reply */
    enum socks_response_status status;

    const int *client_fd;
    int *server_fd;
};

/** Request connecting */
struct connecting {
    buffer *write_buffer;
    const int *client_fd;
    int *server_fd;
    enum socks_response_status *status;
};

/** COPY */
struct copy {
    /** el otro fd */
    int *fd;
    buffer *read_buffer, *write_buffer;

    /** Este campo nos permite ver cual punta esta disponible para lectura o escritura */
    fd_interest duplex;
    struct copy *other;
};

/**
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una única
 * alocación cuando recibimos la conexión.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct socks5 {
    /** informacion del cliente */
    struct sockaddr_storage client_addr;
    int client_fd;

    /** res de la direccion del server */
    struct addrinfo *origin_resolution;
    struct sockaddr server_addr;
    socklen_t server_addr_len;
    int origin_domain;
    int server_fd;

    /** maquinas de estados */
    struct state_machine stm;

    /** estados para el client_fd */
    union {
        struct hello_st hello;
        struct auth_user_pass_st auth_user_pass;
        struct request_st request;
        struct copy copy;
    } client;
    /** estados para el server_fd */
    union {
        struct connecting connecting;
        struct copy copy;
    } server;

    /** buffers para ser usados read_buffer, write_buffer */
    uint8_t raw_buff_a[8*1024], raw_buff_b[8 * 1024];
    buffer read_buffer, write_buffer;

    /** cantidad de referencias a este objecto. == 1 -> eliminar */
    unsigned references;

    /** siguiente en pool */
    struct socks5 *next;
};

/**
 * Pool de struct socks5
 *
 * No hay race conditions porque hay un solo hilo
 */
static const unsigned max_pool = 500;
static unsigned pool_size = 0;
static struct socks5 *pool = NULL;

/** -------------------- DECLARATIONS --------------------- */
/** ---------------- SOCKSV5 ---------------- */
static struct socks5 *socks5_new(int client_fd);
static const struct state_definition *socks5_describe_states();
static void socks5_destroy(struct socks5 *s);
static void socks5_destroy_(struct socks5 *s);

/**
 * Handlers socksv5
 * Declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read(struct selector_key *key);
static void socksv5_write(struct selector_key *key);
static void socksv5_block(struct selector_key *key);
static void socksv5_close(struct selector_key *key);
static void socksv5_done(struct selector_key* key);
static const struct fd_handler socks5_handler = {
        .handle_read   = socksv5_read,
        .handle_write  = socksv5_write,
        .handle_close  = socksv5_close,
        .handle_block  = socksv5_block,
};

/** ---------------- HELLO ---------------- */
static void on_hello_method(struct hello_parser *p, uint8_t method);
static void hello_read_init(unsigned state, struct selector_key *key);
static unsigned hello_read(struct selector_key *key);
static void hello_read_close(unsigned state, struct selector_key *key);
static unsigned hello_process(const struct hello_st *d);
static unsigned hello_write(struct selector_key *key);

/** ---------------- AUTH_USER_PASS ---------------- */
static void auth_user_pass_read_init(unsigned state, struct selector_key *key);
static unsigned auth_user_pass_read(struct selector_key *key);
static void auth_user_pass_read_close(unsigned state, struct selector_key *key);
static unsigned auth_user_pass_process(struct auth_user_pass_st *d);
static unsigned auth_user_pass_write(struct selector_key *key);

/** ---------------- REQUEST ---------------- */
static void request_init(unsigned state, struct selector_key *key);
static unsigned request_read(struct selector_key *key);
static void request_read_close(unsigned state, struct selector_key *key);
static unsigned request_process(struct selector_key *key, struct request_st *d);
static unsigned request_connect(struct selector_key *key, struct request_st *d);
static unsigned request_write(struct selector_key *key);

/** ---------------- REQUEST RESOLVE ---------------- */
static void *request_resolve_blocking(void *data);
static unsigned request_resolve_done(struct selector_key *key);

/** ---------------- REQUEST CONNECTING ---------------- */
static void request_connecting_init(unsigned state, struct selector_key *key);
static unsigned request_connecting_write(struct selector_key *key);

/** ---------------- COPY ---------------- */
static void copy_init(unsigned state, struct selector_key *key);
static unsigned copy_read(struct selector_key *key);
static unsigned copy_write(struct selector_key *key);
static struct copy *copy_ptr(struct selector_key *key);
static fd_interest copy_compute_interests(fd_selector s, struct copy* d);

/** ---------------- SOCKSV5 HANDLERS ---------------- */
static const struct state_definition client_statbl[] = {
        {
                .state            = HELLO_READ,
                .on_arrival       = hello_read_init,
                .on_departure     = hello_read_close,
                .on_read_ready    = hello_read,
        }, {
                .state = HELLO_WRITE,
                .on_write_ready = hello_write,
        }, {
                .state = AUTH_USER_PASS_READ,
                .on_arrival = auth_user_pass_read_init,
                .on_departure = auth_user_pass_read_close,
                .on_read_ready = auth_user_pass_read
        }, {
                .state = AUTH_USER_PASS_WRITE,
                .on_write_ready = auth_user_pass_write
        }, {
                .state = REQUEST_READ,
                .on_arrival = request_init,
                .on_departure = request_read_close,
                .on_read_ready = request_read
        }, {
                .state = REQUEST_RESOLVE,
                .on_block_ready = request_resolve_done
        }, {
                .state = REQUEST_CONNECTING,
                .on_arrival = request_connecting_init,
                .on_write_ready = request_connecting_write
        }, {
                .state = REQUEST_WRITE,
                .on_write_ready = request_write
        }, {
                .state = COPY,
                .on_arrival = copy_init,
                .on_read_ready = copy_read,
                .on_write_ready = copy_write
        }, {
                .state = DONE,
        }, {
                .state = ERROR
        }
};

/** -------------------- DEFINITIONS --------------------- */
/** ---------------- SOCKSV5 ---------------- */
/** ---------------- PUBLIC ---------------- */
void socksv5_pool_destroy() {
    struct socks5 *next, *s;
    for (s = pool; s != NULL; s = next) {
        next = s->next;
        free(s);
    }
}

/** Intenta aceptar la nueva conexión entrante*/
void socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    struct socks5 *state = NULL;

    const int client = accept(key->fd, (struct sockaddr *) &client_addr, &client_addr_len);
    if (client == -1 || selector_fd_set_nio(client) == -1) goto fail;

    state = socks5_new(client);
    if (state == NULL) {
        //TODO
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);

    if (SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler, OP_READ, state)) goto fail;
    return;

    fail:
    if (client != -1) close(client);
    socks5_destroy(state);
}

/** ---------------- PRIVATE ---------------- */
static struct socks5 *socks5_new(int client_fd) {
    struct socks5 *ret;

    if (pool == NULL) {
        ret = calloc(sizeof(*ret), 1);
        if (ret == NULL) return NULL;
    } else {
        ret = pool;
        pool = pool->next;
        ret->next = NULL;
        memset(ret, 0x00, sizeof(*ret));
    }

    ret->server_fd = -1;
    ret->client_fd = client_fd;

    ret->stm.initial = HELLO_READ;
    ret->stm.max_state = ERROR;
    ret->stm.states = socks5_describe_states();
    stm_init(&ret->stm);

    buffer_init(&ret->read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);

    ret->references = 1;

    return ret;
}

static const struct state_definition *socks5_describe_states() {
    return client_statbl;
}

/**
 * destruye un `struct socks5', tiene en cuenta las referencias  y el pool de objetos.
 */
static void socks5_destroy(struct socks5 *s) {
    if (s != NULL) {
        if (s->references == 1) {
            if (s != NULL) {
                if (pool_size < max_pool) {
                    s->next = pool;
                    pool = s;
                    pool_size++;
                } else {
                    socks5_destroy_(s);
                }
            }
        } else {
            s->references -= 1;
        }
    }
}

/** realmente destruye */
static void socks5_destroy_(struct socks5 *s) {
    if (s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

/**
 * Handlers socksv5
 * Declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 * Handlers top level de la conexión pasiva.
 * son los que emiten los eventos a la maquina de estados.
 */
static void socksv5_read(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_read(stm, key);

    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void socksv5_write(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);

    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void socksv5_block(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

static void socksv5_done(struct selector_key* key) {
    const int fds[] = {
            ATTACHMENT(key)->client_fd,
            ATTACHMENT(key)->server_fd,
    };
    for (unsigned i = 0; i < N(fds); i++) {
        if (fds[i] != -1) {
            if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}


/** ---------------- HELLO ---------------- */
/** callback del parser utilizado en `read_hello' */
static void on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t *selected = p->data;

    // Prioritize Username and password authentication method
    if (*selected == SOCKS_HELLO_METHOD_USERNAME_PASSWORD)
        return;
    if (*selected == SOCKS_HELLO_METHOD_USERNAME_PASSWORD)
        *selected = method;

    if (method == SOCKS_HELLO_METHOD_NO_AUTHENTICATION_REQUIRED) {
        *selected = method;
    }
}

/** inicializa las variables de los estados HELLO_... */
static void hello_read_init(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;

    d->method = SOCKS_HELLO_METHOD_NO_ACCEPTABLE_METHODS;
    d->read_buffer = &(ATTACHMENT(key)->read_buffer);
    d->write_buffer = &(ATTACHMENT(key)->write_buffer);
    d->parser.data = &d->method;
    d->parser.on_authentication_method = on_hello_method;

    hello_parser_init(&d->parser);
}

/** lee todos los bytes del mensaje de tipo `parser' y inicia su proceso */
static unsigned hello_read(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned ret = HELLO_READ;
    bool error = false;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(d->read_buffer, &count);
    n = recv(key->fd, ptr, count, 0);
    if (n > 0) {
        buffer_write_adv(d->read_buffer, n);
        const enum hello_state st = hello_consume(d->read_buffer, &d->parser, &error);
        if (hello_is_done(st, NULL)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = hello_process(d);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

static void hello_read_close(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    hello_parser_close(&d->parser);
}

/** procesamiento del mensaje `parser' */
static unsigned hello_process(const struct hello_st *d) {
    unsigned ret = HELLO_WRITE;

    uint8_t m = d->method;
    if (hello_write_response(d->write_buffer, m) == -1) {
        ret = ERROR;
    }
    return ret;
}

static unsigned hello_write(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned ret = HELLO_WRITE;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_read_ptr(d->write_buffer, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL); // Usamos el flag porque no queremos que termine en un SIGPIPE
    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(d->write_buffer, n);
        if (!buffer_can_read(d->write_buffer)) {
            if (selector_set_interest_key(key, OP_READ) == SELECTOR_SUCCESS) {
                if (d->method == SOCKS_HELLO_METHOD_USERNAME_PASSWORD)
                    ret = AUTH_USER_PASS_READ;
                else
                    ret = REQUEST_READ;
            } else {
                ret = ERROR;
            }
        }
    }

    return ret;
}


/** ---------------- AUTH_USER_PASS ---------------- */
static void auth_user_pass_read_init(const unsigned state, struct selector_key *key) {
    struct auth_user_pass_st *d = &ATTACHMENT(key)->client.auth_user_pass;

    d->read_buffer = &(ATTACHMENT(key)->read_buffer);
    d->write_buffer = &(ATTACHMENT(key)->write_buffer);

    auth_user_pass_parser_init(&d->parser);
}

/** lee todos los bytes del mensaje de tipo `parser' y inicia su proceso */
static unsigned auth_user_pass_read(struct selector_key *key) {
    struct auth_user_pass_st *d = &ATTACHMENT(key)->client.auth_user_pass;
    unsigned ret = AUTH_USER_PASS_READ;
    bool error = false;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(d->read_buffer, &count);
    n = recv(key->fd, ptr, count, 0);
    if (n > 0) {
        buffer_write_adv(d->read_buffer, n);
        const enum auth_user_pass_state st = auth_user_pass_parser_consume(d->read_buffer, &d->parser, &error);
        if (auth_user_pass_parser_is_done(st, NULL)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = auth_user_pass_process(d);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

static void auth_user_pass_read_close(const unsigned state, struct selector_key *key) {
    struct auth_user_pass_st *d = &ATTACHMENT(key)->client.auth_user_pass;
    auth_user_pass_parser_close(&d->parser);
}

static unsigned auth_user_pass_process(struct auth_user_pass_st *d) {
    if (!auth_user_pass_parser_set_credentials(&d->parser, &d->credentials))
        return ERROR;

    uint8_t status = auth_user_pass_helper_verify(&d->credentials) == AUTH_USER_PASS_HELPER_OK ?
            AUTH_USER_PASS_STATUS_CREDENTIALS_OK : AUTH_USER_PASS_STATUS_INVALID_CREDENTIALS;
    if (auth_user_pass_parser_close_write_response(d->write_buffer, status) == -1) {
        return ERROR;
    }
    return AUTH_USER_PASS_WRITE;
}

static unsigned auth_user_pass_write(struct selector_key *key) {
    struct auth_user_pass_st *d = &ATTACHMENT(key)->client.auth_user_pass;
    unsigned ret = REQUEST_READ;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_read_ptr(d->write_buffer, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(d->write_buffer, n);
        if (!buffer_can_read(d->write_buffer)) {
            if (selector_set_interest_key(key, OP_READ) == SELECTOR_SUCCESS) {
                ret = REQUEST_READ;
            } else {
                ret = ERROR;
            }
        }
    }

    return ret;
}


/** ---------------- REQUEST ---------------- */
static void request_init(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

    d->read_buffer = &ATTACHMENT(key)->read_buffer;
    d->write_buffer = &ATTACHMENT(key)->write_buffer;
    d->parser.request = &d->request;
    d->status = socks_status_general_SOCKS_server_failure;

    d->client_fd = &ATTACHMENT(key)->client_fd;
    d->server_fd = &ATTACHMENT(key)->server_fd;

    request_parser_init(&d->parser);
}

static unsigned request_read(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

    unsigned ret = REQUEST_READ;
    bool error = false;
    uint8_t *ptr;
    size_t count;

    ptr = buffer_write_ptr(d->read_buffer, &count);
    count = recv(key->fd, ptr, count, 0);
    if (count > 0) {
        buffer_write_adv(d->read_buffer, count);
        enum request_state st = request_parser_consume(d->read_buffer, &d->parser, &error);
        if (request_parser_is_done(st, NULL)) {
            ret = request_process(key, d);
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

static void request_read_close(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    request_parser_close(&d->parser);
}

static unsigned request_process(struct selector_key *key, struct request_st *d) {
    struct selector_key *key_copy = NULL;
    struct sockaddr_in *in = NULL;
    struct sockaddr_in6 *in6 = NULL;

    switch (d->request.cmd) {
        case REQUEST_CMD_CONNECT:
            switch (d->request.address_type) {
                case REQUEST_ATYP_IPV4:
                    in = (struct sockaddr_in *) &d->request.dest_addr;

                    ATTACHMENT(key)->origin_domain = AF_INET;
                    in->sin_port = htons(d->request.port);
                    ATTACHMENT(key)->server_addr_len = sizeof(d->request.dest_addr);
                    memcpy(&ATTACHMENT(key)->server_addr, &d->request.dest_addr, sizeof(d->request.dest_addr));
                    return request_connect(key, d);
                case REQUEST_ATYP_IPV6:
                    in6 = (struct sockaddr_in6 *) &d->request.dest_addr;

                    ATTACHMENT(key)->origin_domain = AF_INET6;
                    in6->sin6_port = htons(d->request.port);
                    ATTACHMENT(key)->server_addr_len = sizeof(d->request.dest_addr);
                    memcpy(&ATTACHMENT(key)->server_addr, &d->request.dest_addr, sizeof(d->request.dest_addr));
                    return request_connect(key, d);
                case REQUEST_ATYP_DOMAIN_NAME:
                    key_copy = malloc(sizeof(*key));
                    if (key_copy == NULL) {
                        d->status = socks_status_general_SOCKS_server_failure;
                        selector_set_interest_key(key, OP_WRITE);
                        return REQUEST_WRITE;
                    } else {
                        pthread_t thread_id;
                        memcpy(key_copy, key, sizeof(*key_copy));
                        if (pthread_create(&thread_id, 0, request_resolve_blocking, key_copy) != 0) {
                            d->status = socks_status_general_SOCKS_server_failure;
                            selector_set_interest_key(key, OP_WRITE);
                            return REQUEST_WRITE;
                        } else {
                            selector_set_interest_key(key, OP_NOOP);
                            return REQUEST_RESOLVE;
                        }
                    }
                default:
                    d->status = socks_status_address_type_not_supported;
                    selector_set_interest_key(key, OP_WRITE);
                    return REQUEST_WRITE;
            }
        case REQUEST_CMD_BIND:
        case REQUEST_CMD_UDP_ASSOCIATE:
        default:
            d->status = socks_status_command_not_supported;
            return REQUEST_WRITE;
    }
}

static unsigned request_connect(struct selector_key *key, struct request_st *d) {
    bool error = false;
    enum socks_response_status status = d->status;
    int *fd = d->server_fd;

    *fd = socket(ATTACHMENT(key)->origin_domain, SOCK_STREAM, 0);
    if (*fd == -1 || selector_fd_set_nio(*fd) == -1) {
        error = true;
        goto finally;
    }
    if (connect(*fd, (const struct sockaddr*) &ATTACHMENT(key)->server_addr, ATTACHMENT(key)->server_addr_len) == -1) {
        if (errno == EINPROGRESS) {
            /** Nos llega este error porque estamos en async */
            selector_status st = selector_set_interest_key(key, OP_NOOP);
            if (st != SELECTOR_SUCCESS) {
                error = true;
                goto finally;
            }

            st = selector_register(key->s, *fd, &socks5_handler, OP_WRITE, key->data);
            if (st != SELECTOR_SUCCESS) {
                error = true;
                goto finally;
            }
            ATTACHMENT(key)->references += 1;
        } else {
            status = errno_to_socks(errno);
            error = true;
        }
    } else {
        abort();
    }

    finally:
    if (error) {
        if (*fd != -1) {
            close(*fd);
            *fd = -1;
        }
    }

    d->status = status;

    return REQUEST_CONNECTING;
}

static unsigned request_write(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    unsigned ret = REQUEST_READ;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_read_ptr(d->write_buffer, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(d->write_buffer, n);
        if (!buffer_can_read(d->write_buffer)) {
            if (d->status == socks_status_succeeded) {
                ret = COPY;
                selector_set_interest(key->s, *d->client_fd, OP_READ);
                selector_set_interest(key->s, *d->server_fd, OP_READ);
            } else {
                ret = DONE;
                selector_set_interest(key->s, *d->client_fd, OP_NOOP);
                if (*d->server_fd != -1) {
                    selector_set_interest(key->s, *d->server_fd, OP_NOOP);
                }
            }
        }
    }

    // TODO: Log req

    return ret;
}


/** ---------------- REQUEST RESOLVE ---------------- */
static void *request_resolve_blocking(void *data) {
    struct selector_key *key = (struct selector_key*) data;
    struct socks5 *s = ATTACHMENT(key);

    pthread_detach(pthread_self());
    s->origin_resolution = NULL;
    struct addrinfo hints = {
            .ai_family = AF_UNSPEC, // IPv4 OR IPv6
            .ai_socktype = SOCK_STREAM, // Datagram socket
            .ai_flags = AI_PASSIVE, // Wildcard IP Address
            .ai_protocol = 0,
            .ai_canonname = NULL,
            .ai_addr = NULL,
            .ai_next = NULL
    };

    char buffer[7];
    snprintf(buffer, sizeof(buffer), "%d", ntohs(s->client.request.request.port));
    getaddrinfo(s->client.request.request.domain_name, buffer, &hints, &s->origin_resolution);
    selector_notify_block(key->s, key->fd);
    free(data);
    return 0;
}

/** procesa el resultado de la resoluicion de nombres */
static unsigned request_resolve_done(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    struct socks5 *s = ATTACHMENT(key);

    if (s->origin_resolution == NULL) {
        d->status = socks_status_general_SOCKS_server_failure;
    } else {
        s->origin_domain = s->origin_resolution->ai_family;
        s->server_addr_len = s->origin_resolution->ai_addrlen;
        memcpy(&s->server_addr, s->origin_resolution->ai_addr, s->origin_resolution->ai_addrlen);
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = NULL;
    }

    return request_connect(key, d);
}


/** ---------------- REQUEST CONNECTING ---------------- */
static void request_connecting_init(const unsigned state, struct selector_key *key) {
    struct connecting *d = &ATTACHMENT(key)->server.connecting;

    d->client_fd = &ATTACHMENT(key)->client_fd;
    d->server_fd = &ATTACHMENT(key)->server_fd;
    d->status = &ATTACHMENT(key)->client.request.status;
    d->write_buffer = &ATTACHMENT(key)->write_buffer;
}

static unsigned request_connecting_write(struct selector_key *key) {
    int error;
    socklen_t len = sizeof(error);
    struct connecting *d = &ATTACHMENT(key)->server.connecting;

    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        *d->status = socks_status_general_SOCKS_server_failure;
    } else {
        if (error == 0) {
            *d->status = socks_status_succeeded;
            *d->server_fd = key->fd;
        } else {
            *d->status = errno_to_socks(error);
        }
    }

    if (request_parser_write_response(d->write_buffer, &ATTACHMENT(key)->client_addr, *d->status) == -1) {
        *d->status = socks_status_general_SOCKS_server_failure;
        abort(); // El fubber tiene que ser mas grande en la variable
    }
    selector_status s = 0;
    s |= selector_set_interest(key->s, *d->client_fd, OP_WRITE);
    s |= selector_set_interest_key(key, OP_NOOP);
    return s == SELECTOR_SUCCESS ? REQUEST_WRITE : ERROR;
}

/** ---------------- COPY ---------------- */
static void copy_init(const unsigned state, struct selector_key *key) {
    struct copy *d = &ATTACHMENT(key)->client.copy;

    d->fd = &ATTACHMENT(key)->client_fd;
    d->read_buffer = &ATTACHMENT(key)->read_buffer;
    d->write_buffer = &ATTACHMENT(key)->write_buffer;
    d->duplex = OP_READ | OP_WRITE;
    d->other = &ATTACHMENT(key)->server.copy;

    d = &ATTACHMENT(key)->server.copy;
    d->fd = &ATTACHMENT(key)->server_fd;
    d->read_buffer = &ATTACHMENT(key)->write_buffer;
    d->write_buffer = &ATTACHMENT(key)->read_buffer;
    d->duplex = OP_READ | OP_WRITE;
    d->other = &ATTACHMENT(key)->client.copy;
}

/** lee bytes de un socket y los encola para ser escritos en otro */
static unsigned copy_read(struct selector_key *key) {
    struct copy *d = copy_ptr(key);

    assert(*d->fd == key->fd);
    size_t size;
    ssize_t n;
    unsigned ret = COPY;

    uint8_t *ptr = buffer_write_ptr(d->read_buffer, &size);
    n = send(key->fd, ptr, size, 0);
    if (n <= 0) {
        shutdown(*d->fd, SHUT_RD);
        d->duplex &= ~OP_READ;
        if (*d->other->fd != -1) {
            shutdown(*d->other->fd, SHUT_WR);
            d->other->duplex &= ~OP_WRITE;
        }
    } else {
        buffer_write_adv(d->read_buffer, n);
    }

    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);
    if (d->duplex == OP_NOOP) {
        ret = DONE;
    }
    return ret;
}

/** Escribe bytes encolados */
static unsigned copy_write(struct selector_key *key) {
    struct copy *d = copy_ptr(key);

    assert(*d->fd == key->fd);
    size_t size;
    ssize_t n;
    unsigned ret = COPY;

    uint8_t *ptr = buffer_read_ptr(d->write_buffer, &size);
    n = send(key->fd, ptr, size, MSG_NOSIGNAL);
    if (n == -1) {
        shutdown(*d->fd, SHUT_WR);
        d->duplex &= ~OP_WRITE;
        if (*d->other->fd != -1) {
            shutdown(*d->other->fd, SHUT_RD);
            d->other->duplex &= ~OP_READ;
        }
    } else {
        buffer_read_adv(d->write_buffer, n);
    }
    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);
    if (d->duplex == OP_NOOP) {
        ret = DONE;
    }
    return ret;
}

/** elige la estructura de copia correcta de cada fd (server o client) */
static struct copy *copy_ptr(struct selector_key *key) {
    struct copy *d = &ATTACHMENT(key)->client.copy;
    if (*d->fd != key->fd) {
        d = d->other;
    }
    return d;
}

/**
 * Computa los intereses en base a la disponibilidad de los buffer.
 */
static fd_interest copy_compute_interests(fd_selector s, struct copy* d) {
    fd_interest ret = OP_NOOP;

    if ((d->duplex & OP_READ) && buffer_can_write(d->read_buffer)) {
        ret |= OP_READ;
    }
    if ((d->duplex & OP_WRITE) && buffer_can_read(d->write_buffer)) {
        ret |= OP_WRITE;
    }
    if (SELECTOR_SUCCESS != selector_set_interest(s, *d->fd, ret)) {
        abort();
    }
    return ret;
}
