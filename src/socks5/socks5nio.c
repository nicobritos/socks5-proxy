/**
 * socks5nio.c  - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 */
#include <stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <unistd.h>  // close

#include <arpa/inet.h>

#include "message/parser/hello_parser.h"
#include "message/parser/auth_user_pass_parser.h"
#include "message/parser/request_parser.h"

#include "../utils/stm.h"
#include "socks5nio.h"
#include "../utils/byte_formatter.h"
#include "../doh/doh.h"
#include "../configuration.h"
#include "sniffer/http_sniffer.h"
#include "sniffer/pop3_sniffer.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define MIN(x, y) (x < y ? x : y)
/** obtiene el struct (socks5 *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)
#define SOCKS_LOG_FILENAME "socks.log"
#define HTTP_PROTOCOL "HTTP"
#define POP3_PROTOCOL "POP3"


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
     *   - REQUEST_RESOLVE_CONNECT  si requiere resolver un nombre DNS
     *   - REQUEST_CONNECT si no requiere resolver DNS
     *   - REQUEST_WRITE  si determinamos que no se puede procesar
     *   - ERROR
     */
    REQUEST_READ,

    /**
     * Aqui nos conectamos al servidor DNS
     * Intereses:
     *   - OP_NOOP sobre el client_fd
     * Transiciones:
     *   - REQUEST_RESOLVE_WRITE si se pudo conectar
     *   - REQUEST_WRITE sino (y setea el status)
     */
    REQUEST_RESOLVE_CONNECT,

    /**
     * Aqui esperamos la resoluicion DNS
     * Intereses:
     *   - OP_NOOP sobre el client_fd
     *   - OP_WRITE sobre el dns.fd
     * Transiciones:
     *   - REQUEST_RESOLVE_WRITE mientras hayan bytes por escribir
     *   - REQUEST_RESOLVE_READ sino
     *   - REQUEST_WRITE si se produjo algun error
     */
    REQUEST_RESOLVE_WRITE,

    /**
     * Aqui esperamos la resoluicion DNS
     * Intereses:
     *   - OP_NOOP sobre el client_fd
     *   - OP_READ sobre el dns.fd
     * Transiciones:
     *   - REQUEST_RESOLVE_READ mientras hayan bytes por leer
     *   - REQUEST_WRITE si ya termino o si se produjo algun error
     */
    REQUEST_RESOLVE_READ,

    /**
     * Espera a que se establezca la conexion al servidor
     * Intereses:
     *   - OP_WRITE sobre client_fd
     * Transiciones:
     *   - REQUEST_WRITE
     */
    REQUEST_CONNECT,

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
     *   - COPY
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
    struct auth_user_pass_credentials *credentials;
};

struct request_st {
    buffer *read_buffer;
    buffer *write_buffer;

    /** aqui guardamos la info de la request (address, port, cmd) */
    const struct request request;
    /** parser */
    struct request_parser parser;

    /** status, campo de reply */
    enum socks_response_status status;

    const int *client_fd;
    int *server_fd;
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
    struct {
        struct doh_response *origin_resolution;
        uint8_t *response_buffer;
        char *request;
        ssize_t request_len;
        ssize_t write_index;
        ssize_t read_index;
        int fd;
        uint8_t ipv4_index;
        uint8_t ipv6_index;
    } dns;
    struct sockaddr_storage server_addr;
    socklen_t server_addr_len;
    int server_fd;

    /** maquinas de estados */
    struct state_machine stm;

    /** estados para el client_fd */
    union {
        struct hello_st hello;
        struct auth_user_pass_st auth_user_pass;
        struct copy copy;
    } client;

    struct request_st client_request;
    struct {
        struct {
            struct pop3_credentials credentials;
            struct parser *parser;
        } pop3_data;

        struct http_credentials http_credentials;

        bool done;
    } client_sniffers;

    /** estados para el server_fd */
    union {
        struct copy copy;
    } server;

    struct auth_user_pass_credentials credentials;

    /** buffers para ser usados read_buffer, write_buffer */
    uint8_t raw_buff_a[8*1024], raw_buff_b[8 * 1024];
    buffer read_buffer, write_buffer;

    uint64_t bytes_downloaded;
    uint64_t bytes_uploaded;

    /** cantidad de referencias a este objecto. == 1 -> eliminar */
    uint32_t references;

    /** siguiente en pool */
    struct socks5 *next;
};

typedef struct socks_access_log_t {
    socks_access_log_node_t first;
    socks_access_log_node_t last;
} socks_access_log_t;

typedef struct socks_access_log_node_CDT {
    struct socks_access_log_details_t details;
    socks_access_log_node_t next;
} socks_access_log_node_CDT;

/**
 * Pool de struct socks5
 *
 * No hay race conditions porque hay un solo hilo
 */
static const uint32_t max_pool = 500;
static uint32_t pool_size = 0;
static struct socks5 *pool = NULL;
static log_t logger;
static uint64_t max_clients, current_clients, bytes_transferred;
static sniffed_credentials_list sniffed_credentials_l;
static socks_access_log_t access_log;

/** -------------------- DECLARATIONS --------------------- */
/** ---------------- SOCKSV5 ---------------- */
static struct socks5 *socks5_new(int client_fd);
static const struct state_definition *socks5_describe_states();
static void socks5_destroy(struct socks5 *s);
static void socks5_destroy_(struct socks5 *s);

/**
 * Escribe la IP en el buffer y almacena el puerto en una variable.
 * @param s
 * @param buffer
 * @param port
 * @return false si hubo un error
 */
static bool extract_ip_port_(const struct sockaddr_storage *s, char *buffer, uint16_t *port);

/**
 * Handlers socksv5
 * Declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read(struct selector_key *key);
static void socksv5_write(struct selector_key *key);
static void socksv5_close(struct selector_key *key);
static void socksv5_done(struct selector_key* key);
static void close_fd_(int fd, struct selector_key* key);
static void log_close(const struct selector_key *key);
static const struct fd_handler socks5_handler = {
        .handle_read   = socksv5_read,
        .handle_write  = socksv5_write,
        .handle_close  = socksv5_close,
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
static unsigned auth_user_pass_process(struct auth_user_pass_st *d, const struct selector_key *key);
static unsigned auth_user_pass_write(struct selector_key *key);

/** ---------------- REQUEST ---------------- */
static void request_init(unsigned state, struct selector_key *key);
static unsigned request_read(struct selector_key *key);
static unsigned request_process(struct selector_key *key, struct request_st *d);
static unsigned request_connect(struct selector_key *key, struct request_st *d);
static unsigned request_write(struct selector_key *key);
static void request_write_close(unsigned state, struct selector_key *key);
/** Este metodo tambien logguea al access log */
static void log_request(const struct selector_key *key, const struct request_parser *p, enum socks_response_status socks_status);

/** ---------------- REQUEST RESOLVE ---------------- */
static enum socks_v5state request_resolve_connect(struct selector_key *key, struct request_st *d);
static void request_resolve_read_init(unsigned state, struct selector_key *key);
static unsigned request_resolve_read(struct selector_key *key);
static void request_resolve_read_close(unsigned state, struct selector_key *key);
static unsigned request_resolve_connect_write(struct selector_key *key);
static void request_write_init(const unsigned int state, struct selector_key *key);
static unsigned request_resolve_write(struct selector_key *key);
static unsigned request_resolve_process(struct selector_key *key, struct request_st *d);
static unsigned request_resolve_set_address(struct selector_key *key, struct doh_response *doh);

/** ---------------- REQUEST CONNECTING ---------------- */
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
                .on_read_ready = request_read
        }, {
                .state = REQUEST_RESOLVE_CONNECT,
                .on_write_ready = request_resolve_connect_write // Esto va a escribir en el buffer
        }, {
                .state = REQUEST_RESOLVE_WRITE,
                .on_write_ready = request_resolve_write // Esto va a mandar del buffer
        }, {
                .state = REQUEST_RESOLVE_READ,
                .on_arrival = request_resolve_read_init,
                .on_read_ready = request_resolve_read,
                .on_departure = request_resolve_read_close
        }, {
                .state = REQUEST_CONNECT,
                .on_write_ready = request_connecting_write
        }, {
                .state = REQUEST_WRITE,
                .on_arrival = request_write_init,
                .on_write_ready = request_write,
                .on_departure = request_write_close
        }, {
                .state = COPY,
                .on_arrival = copy_init,
                .on_read_ready = copy_read,
                .on_write_ready = copy_write,
        }, {
                .state = DONE,
        }, {
                .state = ERROR
        }
};

/** -------------------- DEFINITIONS --------------------- */
/** ---------------- SOCKSV5 ---------------- */
/** ---------------- PUBLIC ---------------- */
void socks_init() {
    logger = logger_init_log(SOCKS_LOG_FILENAME, DEFAULT_LOG_LEVEL);
    sniffed_credentials_l = sniffed_credentials_create_list();
    if (sniffed_credentials_l == NULL && logger != NULL) {
        logger_append_to_log(
                logger,
                log_severity_warning,
                "No se pudo crear el listado para almacenar las contrasenas sniffeadas",
                0);
    }

    access_log.first = access_log.last = NULL;
}

/**
 * Devuelve el primer nodo del access log
 * @return
 */
socks_access_log_node_t socks_get_first_access_log_node() {
    return access_log.first;
}

/**
 * Devuelve el siguiente nodo del access log
 * @param node
 * @return
 */
socks_access_log_node_t socks_get_next_access_log_node(socks_access_log_node_t node) {
    return node != NULL ? node->next : NULL;
}

/**
 * Devuelve el access log asociado al nodo
 * @param node
 * @return
 */
struct socks_access_log_details_t *socks_get_access_log(socks_access_log_node_t node) {
    return node != NULL ? &node->details : NULL;
}

/**
 * Devuelve el logger del socks o NULL si no esta inicializado
 * @return
 */
log_t socks_get_log() {
    return logger;
}

/**
 * Devuelve la cantidad total de clientes que se conectaron
 * desde que se inicio el servidor
 * @return
 */
uint64_t socks_get_total_connections() {
    return max_clients;
}

/**
 * Devuelve la cantidad de clientes conectados en el momento
 * @return
 */
uint64_t socks_get_current_connections() {
    return current_clients;
}

/**
 * Devuelve la cantidad total de bytes transferidos (down + up)
 * @return
 */
uint64_t socks_get_total_bytes_transferred() {
    return bytes_transferred;
}

/**
 * Devuelve una lista de sniffed credentials
 * @return
 */
sniffed_credentials_list socks_get_sniffed_credentials_list() {
    return sniffed_credentials_l;
}

void socks_pool_destroy() {
    struct socks5 *next, *s;

    for (s = pool; s != NULL; s = next) {
        next = s->next;
        free(s);
    }

    if (logger != NULL) {
        logger_close_log(logger);
        logger = NULL;
    }

    if (sniffed_credentials_l != NULL) {
        sniffed_credentials_node node = sniffed_credentials_get_first(sniffed_credentials_l);

        while (node != NULL) {
            struct sniffed_credentials *credentials = sniffed_credentials_get(node);
            free(credentials->username);
            free(credentials->password);
            free(credentials->logger_user);
            free(credentials->datetime);
            node = sniffed_credentials_get_next(node);
        }

        sniffed_credentials_destroy(sniffed_credentials_l);
        sniffed_credentials_l = NULL;
    }

    socks_access_log_node_t aux_node, node = access_log.first;
    while (node != NULL) {
        aux_node = node->next;
        free(node->details.username);
        free(node->details.datetime);
        free(node->details.destination.name);
        free(node);
        node = aux_node;
    }
    access_log.first = access_log.last = NULL;
}

/** Intenta aceptar la nueva conexión entrante*/
void socks_passive_accept(struct selector_key *key) {
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

    current_clients++;
    max_clients++;

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
            if (pool_size < max_pool) {
                s->next = pool;
                pool = s;
                pool_size++;
            } else {
                socks5_destroy_(s);
            }

            current_clients--;
        } else {
            s->references -= 1;
        }
    }
}

/** realmente destruye */
static void socks5_destroy_(struct socks5 *s) {
    free(s);
}

/**
 * Escribe la IP en el buffer y almacena el puerto en una variable.
 * @param s
 * @param buffer
 * @param port
 * @return false si hubo un error
 */
static bool extract_ip_port_(const struct sockaddr_storage *s, char *buffer, uint16_t *port) {
    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;
    if (s->ss_family == AF_INET) {
        in = (struct sockaddr_in *) s;
        *port = in->sin_port;
        return inet_ntop(AF_INET, &in->sin_addr, buffer, INET_ADDRSTRLEN);
    } else if (s->ss_family == AF_INET6) {
        in6 = (struct sockaddr_in6 *) s;
        *port = in6->sin6_port;
        return inet_ntop(AF_INET6, &in6->sin6_addr, buffer, INET6_ADDRSTRLEN);
    }
    return false;
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

static void socksv5_close(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    
    if (s->references == 1) {
        if (s->client_fd != -1) {
            log_close(key);
        }

        request_parser_close(&s->client_request.parser);
        if (s->credentials.username != NULL) {
            free(s->credentials.username);
            s->credentials.username = NULL;
        }
        if (s->credentials.password != NULL) {
            free(s->credentials.password);
            s->credentials.password = NULL;
        }
        if (s->dns.origin_resolution != NULL) {
            doh_response_parser_free(s->dns.origin_resolution);
            s->dns.origin_resolution = NULL;
        }
        if (s->dns.response_buffer != NULL) {
            free(s->dns.response_buffer);
            s->dns.response_buffer = NULL;
        }
        if (s->dns.request != NULL) {
            free(s->dns.request);
            s->dns.request = NULL;
        }
        if (s->client_sniffers.pop3_data.parser != NULL) {
            pop3_sniffer_destroy(s->client_sniffers.pop3_data.parser);
            s->client_sniffers.pop3_data.parser = NULL;
        }
        free_pop3_credentials(&s->client_sniffers.pop3_data.credentials);
        free_http_credentials(&s->client_sniffers.http_credentials);
    }
    socks5_destroy(s);
}

static void socksv5_done(struct selector_key* key) {
    /**
     * Cuando hacemos close_fd_ no sabemos si ya se libero el
     * socket, entonces nos guardamos las referencias. Si es 0
     * entonces ya fue liberado.
     */
    uint32_t references = ATTACHMENT(key)->references;
    if (ATTACHMENT(key)->client_fd != -1) {
        close_fd_(ATTACHMENT(key)->client_fd, key);
        references--;
        if (references == 0) return;
        ATTACHMENT(key)->client_fd = -1;
    }
    if (ATTACHMENT(key)->server_fd != -1) {
        close_fd_(ATTACHMENT(key)->server_fd, key);
        references--;
        if (references == 0) return;
        ATTACHMENT(key)->server_fd = -1;
    }
}

static void close_fd_(int fd, struct selector_key* key) {
    if (fd != -1) {
        if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, fd)) {
            return;
        }
        close(fd);
    }
}

static void log_close(const struct selector_key *key) {
    const struct socks5 *s = ATTACHMENT(key);

    if (logger != NULL) {
        char ip_buffer_client[INET6_ADDRSTRLEN];
        uint16_t port_client;
        if (!extract_ip_port_(&s->client_addr, ip_buffer_client, &port_client)) {
            return;
        }

        double formatted_bytes_download;
        double formatted_bytes_upload;
        const char *bytes_download_multiplier = byte_formatter_format(s->bytes_downloaded, &formatted_bytes_download);
        const char *bytes_upload_multiplier = byte_formatter_format(s->bytes_uploaded, &formatted_bytes_upload);
        if (s->credentials.username != NULL) {
            logger_append_to_log(
                    logger,
                    log_severity_info,
                    "El usuario: %s con ip: %s y puerto %d se ha desconectado. Bytes transferidos: %.3f%s download, %.3f%s upload",
                    7,
                    s->credentials.username,
                    ip_buffer_client,
                    port_client,
                    formatted_bytes_download,
                    bytes_download_multiplier,
                    formatted_bytes_upload,
                    bytes_upload_multiplier
            );
        } else {
            logger_append_to_log(
                    logger,
                    log_severity_info,
                    "El usuario con ip: %s y puerto %d se ha desconectado. Bytes transferidos: %.3f%s download, %.3f%s upload",
                    6,
                    ip_buffer_client,
                    port_client,
                    formatted_bytes_download,
                    bytes_download_multiplier,
                    formatted_bytes_upload,
                    bytes_upload_multiplier
            );
        }
    }
}


/** ---------------- HELLO ---------------- */
/** callback del parser utilizado en `read_hello' */
static void on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t *selected = p->data;

    if (method == SOCKS_HELLO_METHOD_USERNAME_PASSWORD)
        *selected = method;
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
                if (d->method == SOCKS_HELLO_METHOD_USERNAME_PASSWORD) {
                    ret = AUTH_USER_PASS_READ;
                } else {
                    ret = REQUEST_READ;
                    if (logger != NULL) {
                        char ip_buffer[INET6_ADDRSTRLEN];
                        uint16_t port;
                        if (extract_ip_port_(&ATTACHMENT(key)->client_addr, ip_buffer, &port)) {
                            logger_append_to_log(
                                    logger,
                                    log_severity_info,
                                    "El usuario con ip: %s y puerto %d se conecto sin autenticacion",
                                    2,
                                    ip_buffer,
                                    port
                            );
                        }
                    }
                }
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
    d->credentials = &(ATTACHMENT(key))->credentials;

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
                ret = auth_user_pass_process(d, key);
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

static unsigned auth_user_pass_process(struct auth_user_pass_st *d, const struct selector_key *key) {
    if (!auth_user_pass_parser_set_credentials(&d->parser, d->credentials))
        return ERROR;

    uint8_t status = auth_user_pass_helper_verify(d->credentials) ?
            AUTH_USER_PASS_STATUS_CREDENTIALS_OK : AUTH_USER_PASS_STATUS_INVALID_CREDENTIALS;

    if (logger != NULL) {
        char ip_buffer[INET6_ADDRSTRLEN];
        uint16_t port;
        if (extract_ip_port_(&ATTACHMENT(key)->client_addr, ip_buffer, &port)) {
            if (status == AUTH_USER_PASS_STATUS_CREDENTIALS_OK) {
                logger_append_to_log(
                        logger,
                        log_severity_info,
                        "El usuario con ip: %s y puerto %d se conecto como %s",
                        3,
                        ip_buffer,
                        port,
                        d->credentials->username
                );
            } else {
                logger_append_to_log(
                        logger,
                        log_severity_info,
                        "El usuario con ip: %s y puerto %d intento conectarse con credenciales invalidas",
                        2,
                        ip_buffer,
                        port
                );
            }
        }
    }

    return auth_user_pass_parser_close_write_response(d->write_buffer, status) != -1 ? AUTH_USER_PASS_WRITE : ERROR;
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
    struct request_st *d = &ATTACHMENT(key)->client_request;

    d->read_buffer = &ATTACHMENT(key)->read_buffer;
    d->write_buffer = &ATTACHMENT(key)->write_buffer;
    d->parser.request = (struct request *) &d->request;
    d->status = socks_status_general_SOCKS_server_failure;

    d->client_fd = &ATTACHMENT(key)->client_fd;
    d->server_fd = &ATTACHMENT(key)->server_fd;

    request_parser_init(&d->parser);
}

static unsigned request_read(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client_request;

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

static unsigned request_process(struct selector_key *key, struct request_st *d) {
    struct sockaddr_in *in = NULL;
    struct sockaddr_in6 *in6 = NULL;

    switch (d->request.cmd) {
        case REQUEST_CMD_CONNECT:
            switch (d->request.address_type) {
                case REQUEST_ATYP_IPV4:
                    in = (struct sockaddr_in *) &d->request.dest_addr;

                    in->sin_family = AF_INET;
                    in->sin_port = htons(d->request.port);
                    ATTACHMENT(key)->server_addr_len = sizeof(d->request.dest_addr);
                    memcpy(&ATTACHMENT(key)->server_addr, &d->request.dest_addr, sizeof(d->request.dest_addr));
                    return request_connect(key, d);
                case REQUEST_ATYP_IPV6:
                    in6 = (struct sockaddr_in6 *) &d->request.dest_addr;

                    in6->sin6_family = AF_INET6;
                    in6->sin6_port = htons(d->request.port);
                    ATTACHMENT(key)->server_addr_len = sizeof(d->request.dest_addr);
                    memcpy(&ATTACHMENT(key)->server_addr, &d->request.dest_addr, sizeof(d->request.dest_addr));
                    return request_connect(key, d);
                case REQUEST_ATYP_DOMAIN_NAME:
                    selector_set_interest_key(key, OP_NOOP);
                    return request_resolve_connect(key, d);
                default:
                    d->status = socks_status_address_type_not_supported;
                    selector_set_interest_key(key, OP_WRITE);
                    return REQUEST_WRITE;
            }
        case REQUEST_CMD_BIND:
        case REQUEST_CMD_UDP_ASSOCIATE:
        default:
            d->status = socks_status_command_not_supported;
            selector_set_interest_key(key, OP_WRITE);
            return REQUEST_WRITE;
    }
}

static unsigned request_connect(struct selector_key *key, struct request_st *d) {
    bool error = false;
    enum socks_response_status status = d->status;
    int *fd = d->server_fd;

    *fd = socket(ATTACHMENT(key)->server_addr.ss_family, SOCK_STREAM, 0);
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

    return REQUEST_CONNECT;
}

static void request_write_init(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client_request;

    if (request_parser_write_response(d->write_buffer, &ATTACHMENT(key)->client_addr, d->status) == -1) {
        abort();
    }

    selector_set_interest(key->s, *d->client_fd, OP_WRITE);
    selector_set_interest(key->s, *d->server_fd, OP_NOOP);
}

static unsigned request_write(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client_request;
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

            log_request(key, &d->parser, d->status);
        }
    }

    return ret;
}

static void request_write_close(unsigned state, struct selector_key *key) {
    request_parser_close(&ATTACHMENT(key)->client_request.parser);
}

static void log_request(const struct selector_key *key, const struct request_parser *p, enum socks_response_status socks_status) {
    const struct socks5 *s = ATTACHMENT(key);

    socks_access_log_node_t node = malloc(sizeof(*node));
    if (node == NULL) {
        goto file_log;
    }
    node->next = NULL;
    node->details.datetime = logger_get_datetime();
    if (node->details.datetime == NULL) {
        free(node);
        goto file_log;
    }

    uint16_t port_client;
    uint16_t port_server;
    if (!extract_ip_port_(&s->client_addr, node->details.origin.ip, &port_client)) {
        free(node->details.datetime);
        free(node);
        goto file_log;
    }
    if (s->client_request.request.address_type == REQUEST_ATYP_DOMAIN_NAME) {
        // Necesitamos copiar el domain name
        uint16_t len = strlen(s->client_request.request.domain_name);
        node->details.destination.name = malloc(sizeof(*node->details.destination.name) * (len + 1));
        if (node->details.destination.name == NULL) {
            free(node->details.datetime);
            free(node);
            goto file_log;
        }
        memcpy(node->details.destination.name, s->client_request.request.domain_name, len + 1);
    } else {
        // Necesitamos extraer la ip
        node->details.destination.name = malloc(sizeof(*node->details.destination.name) * INET6_ADDRSTRLEN);
        if (node->details.destination.name == NULL) {
            free(node->details.datetime);
            free(node);
            goto file_log;
        }
        if (!extract_ip_port_(&s->server_addr, node->details.destination.name, &port_server)) {
            free(node->details.datetime);
            free(node->details.destination.name);
            free(node);
            goto file_log;
        }
    }

    node->details.username = malloc(sizeof(*node->details.username) * (s->credentials.username_length + 1));
    if (node->details.username == NULL) {
        free(node->details.datetime);
        free(node->details.destination.name);
        free(node);
        goto file_log;
    }
    memcpy(node->details.username, s->credentials.username, s->credentials.username_length + 1);

    port_server = s->client_request.request.port;

    snprintf(node->details.origin.port, PORT_DIGITS, "%d", port_client);
    snprintf(node->details.destination.port, PORT_DIGITS, "%d", port_server);
    node->details.origin.port[PORT_DIGITS] = node->details.destination.port[PORT_DIGITS] = '\0';

    node->details.status = socks_status;

    if (access_log.first == NULL) {
        access_log.first = access_log.last = node;
    } else {
        access_log.last->next = node;
        access_log.last = node;
    }

    file_log:
    if (logger != NULL) {
        char ip_buffer_client[INET6_ADDRSTRLEN];
        char ip_buffer_server[INET6_ADDRSTRLEN];
        if (!extract_ip_port_(&s->client_addr, ip_buffer_client, &port_client)
            || !extract_ip_port_(&s->server_addr, ip_buffer_server, &port_server)) {
            return;
        }

        bool errored = false;
        request_parser_is_done(p->_state, &errored);
        const char *socks_status_str = socks_response_status_str(socks_status);
        const char *connected_str = errored ? "no se pudo conectar" : "se conecto";

        if (s->credentials.username != NULL) {
            if (s->client_request.request.address_type == REQUEST_ATYP_DOMAIN_NAME) {
                logger_append_to_log(
                        logger,
                        log_severity_info,
                        "El usuario: %s con ip: %s y puerto %d %s a: %s [%s] al puerto %d [mapeado al %d] con estado: %s",
                        9,
                        s->credentials.username,
                        ip_buffer_client,
                        port_client,
                        connected_str,
                        s->client_request.request.domain_name,
                        ip_buffer_server,
                        s->client_request.request.port,
                        errored ? -1 : port_server,
                        socks_status_str
                );
            } else {
                logger_append_to_log(
                        logger,
                        log_severity_info,
                        "El usuario: %s con ip: %s y puerto %d %s a: %s al puerto %d [mapeado al %d] con estado: %s",
                        8,
                        s->credentials.username,
                        ip_buffer_client,
                        port_client,
                        connected_str,
                        ip_buffer_server,
                        s->client_request.request.port,
                        errored ? -1 : port_server,
                        socks_status_str
                );
            }
        } else {
            if (s->client_request.request.address_type == REQUEST_ATYP_DOMAIN_NAME) {
                logger_append_to_log(
                        logger,
                        log_severity_info,
                        "El usuario con ip: %s y puerto %d %s a: %s [%s] al puerto %d [mapeado al %d] con estado: %s",
                        8,
                        ip_buffer_client,
                        port_client,
                        connected_str,
                        s->client_request.request.domain_name,
                        ip_buffer_server,
                        s->client_request.request.port,
                        errored ? -1 : port_server,
                        socks_status_str
                );
            } else {
                logger_append_to_log(
                        logger,
                        log_severity_info,
                        "El usuario con ip: %s y puerto %d %s a: %s al puerto %d [mapeado al %d] con estado: %s",
                        7,
                        ip_buffer_client,
                        port_client,
                        connected_str,
                        ip_buffer_server,
                        s->client_request.request.port,
                        errored ? -1 : port_server,
                        socks_status_str
                );
            }
        }
    }
}


/** ---------------- REQUEST RESOLVE ---------------- */
static enum socks_v5state request_resolve_connect(struct selector_key *key, struct request_st *d) {
    bool error = false;
    struct socks5 *s = ATTACHMENT(key);
    
    s->dns.fd = socket(configuration.doh.sockaddr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (s->dns.fd < 0 || selector_fd_set_nio(s->dns.fd)) {
        error = true;
        d->status = socks_status_general_SOCKS_server_failure;
        goto finally;
    }

    if (connect(s->dns.fd, (const struct sockaddr*)&configuration.doh.sockaddr, configuration.doh.socklen) < 0) {
        if (errno == EINPROGRESS) {
            /** Nos llega este error porque estamos en async */
            selector_status st = selector_set_interest_key(key, OP_NOOP);
            if (st != SELECTOR_SUCCESS) {
                error = true;
                goto finally;
            }

            st = selector_register(key->s, s->dns.fd, &socks5_handler, OP_WRITE, key->data);
            if (st != SELECTOR_SUCCESS) {
                error = true;
                goto finally;
            }
            ATTACHMENT(key)->references += 1;
        } else {
            d->status = errno_to_socks(errno);
            error = true;
        }
    } else {
        // Esto no puede pasar
        abort();
    }

    finally:
    if (error) {
        selector_set_interest(key->s, s->dns.fd, OP_NOOP);
        selector_set_interest(key->s, s->client_fd, OP_WRITE);
        return REQUEST_WRITE;
    }

    return REQUEST_RESOLVE_CONNECT;
}

static unsigned request_resolve_connect_write(struct selector_key *key) {
    int error;
    socklen_t len = sizeof(error);
    struct request_st *d = &ATTACHMENT(key)->client_request;
    struct socks5 *s = ATTACHMENT(key);

    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        d->status = socks_status_general_SOCKS_server_failure;
    } else {
        if (error == 0) {
            d->status = socks_status_succeeded;
        } else {
            d->status = errno_to_socks(error);
        }
    }

    s->dns.write_index = s->dns.read_index = 0;
    s->dns.request = getRequest(
            &s->dns.request_len,
            s->client_request.request.domain_name,
            configuration.doh.sockaddr.ss_family,
            configuration.doh.domain_name);

    s->dns.response_buffer = calloc(DNS_BUFFER_SIZE, sizeof(*s->dns.response_buffer));
    if (s->dns.response_buffer == NULL) {
        d->status = socks_status_general_SOCKS_server_failure;
        error = 1;
        goto finally;
    } else {
        error = 0;
    }

    selector_status ss = 0;
    finally:
    if (error) {
        ss |= selector_set_interest(key->s, *d->client_fd, OP_WRITE);
        ss |= selector_set_interest(key->s, s->dns.fd, OP_NOOP);
        return ss == SELECTOR_SUCCESS ? REQUEST_WRITE : ERROR;
    } else {
        ss |= selector_set_interest(key->s, *d->client_fd, OP_NOOP);
        ss |= selector_set_interest(key->s, s->dns.fd, OP_WRITE);
        return ss == SELECTOR_SUCCESS ? REQUEST_RESOLVE_WRITE : ERROR;
    }
}

static unsigned request_resolve_write(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *d = &ATTACHMENT(key)->client_request;

    // Send the string to the server
    ssize_t n = send(
            s->dns.fd,
            s->dns.request + s->dns.write_index,
            MIN(s->dns.request_len - s->dns.write_index, DNS_BUFFER_SIZE - 1),
            MSG_NOSIGNAL);
    if (n < 0) {
        // TODO: Log: DNS NO ESTA LEVANTADO
        d->status = socks_status_general_SOCKS_server_failure;
        selector_set_interest(key->s, s->dns.fd, OP_NOOP);
        selector_set_interest(key->s, *d->client_fd, OP_WRITE);
        return REQUEST_WRITE;
    } else {
        s->dns.write_index += n;
        if (s->dns.write_index == s->dns.request_len) {
            selector_set_interest(key->s, s->dns.fd, OP_READ);
            return REQUEST_RESOLVE_READ;
        }
    }

    return REQUEST_RESOLVE_WRITE;
}

static void request_resolve_read_init(const unsigned state, struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *d = &ATTACHMENT(key)->client_request;

    s->dns.origin_resolution = doh_response_parser_init();
    if (s->dns.origin_resolution == NULL) {
        d->status = socks_status_general_SOCKS_server_failure;
        abort();
    }
}

/** procesa el resultado de la resoluicion de nombres */
static unsigned request_resolve_read(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *d = &ATTACHMENT(key)->client_request;

    // Receive response from the server
    ssize_t n = recv(
            s->dns.fd,
            s->dns.response_buffer + s->dns.read_index,
            DNS_BUFFER_SIZE - 1 - s->dns.read_index,
            0);

    if (n <= 0) {
        d->status = socks_status_general_SOCKS_server_failure;
        selector_set_interest(key->s, s->dns.fd, OP_NOOP);
        selector_set_interest(key->s, *d->client_fd, OP_WRITE);
        return REQUEST_WRITE;
    } else {
        doh_response_parser_feed(
                s->dns.origin_resolution,
                s->dns.response_buffer + s->dns.read_index,
                n);

        s->dns.read_index += n;
        if (doh_response_parser_is_done(s->dns.origin_resolution)) {
            if (doh_response_parser_error(s->dns.origin_resolution)) {
                d->status = socks_status_general_SOCKS_server_failure;
                selector_set_interest(key->s, s->dns.fd, OP_NOOP);
                selector_set_interest(key->s, *d->client_fd, OP_WRITE);
                return REQUEST_WRITE;
            } else {
                selector_set_interest(key->s, s->dns.fd, OP_NOOP);
                return request_resolve_process(key, d);
            }
        }
    }

    return REQUEST_RESOLVE_READ;
}

static unsigned request_resolve_process(struct selector_key *key, struct request_st *d) {
    struct socks5 *s = ATTACHMENT(key);
    selector_status ss = 0;

    if (s->dns.origin_resolution->status_code != 200) {
        ss |= selector_set_interest(key->s, *d->client_fd, OP_WRITE);
        ss |= selector_set_interest(key->s, s->dns.fd, OP_NOOP);
        return ss == SELECTOR_SUCCESS ? REQUEST_WRITE : ERROR;
    } else {
        ss |= selector_set_interest(key->s, s->dns.fd, OP_NOOP);
        return ss == SELECTOR_SUCCESS ? request_resolve_set_address(key, s->dns.origin_resolution) : ERROR;
    }
}

static unsigned request_resolve_set_address(struct selector_key *key, struct doh_response *doh) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *d = &s->client_request;

    if (s->dns.ipv4_index < doh->ipv4_qty) {
        struct sockaddr_in *in = (struct sockaddr_in*) &s->server_addr;

        if (s->dns.ipv4_index == 0) {
            s->server_addr_len = sizeof(s->server_addr);
            s->server_addr.ss_family = AF_INET;
            in->sin_port = htons(d->request.port);
        }
        in->sin_addr.s_addr = htonl(doh->ipv4_addr[s->dns.ipv4_index]);
        s->dns.ipv4_index++;

        return request_connect(key, d);
    } else if (s->dns.ipv6_index < doh->ipv6_qty) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6*) &s->server_addr;

        if (s->dns.ipv6_index == 0) {
            s->server_addr_len = sizeof(s->server_addr);
            s->server_addr.ss_family = AF_INET6;
            in6->sin6_port = htons(d->request.port);
        }

        int8_t address_i = 0;
        while (address_i < IP_6_BYTES) {
            in6->sin6_addr.s6_addr[address_i] = doh->ipv6_addr[s->dns.ipv6_index].byte[address_i];
            address_i++;
        }
        s->dns.ipv6_index++;

        return request_connect(key, d);
    } else {
        // ERROR
        selector_status ss = 0;
        d->status = socks_status_host_unreachable;
        ss |= selector_set_interest(key->s, s->client_fd, OP_WRITE);
        return ss == SELECTOR_SUCCESS ? REQUEST_WRITE : ERROR;
    }
}

static void request_resolve_read_close(const unsigned state, struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    if (s->dns.origin_resolution != NULL) {
        doh_response_parser_free(s->dns.origin_resolution);
        s->dns.origin_resolution = NULL;
    }
    if (s->dns.response_buffer != NULL) {
        free(s->dns.response_buffer);
        s->dns.response_buffer = NULL;
    }
    if (s->dns.request != NULL) {
        free(s->dns.request);
        s->dns.request = NULL;
    }
    if (s->dns.fd != -1) {
        close_fd_(s->dns.fd, key);
        s->dns.fd = -1;
    }
}

/** ---------------- REQUEST CONNECTING ---------------- */
static unsigned request_connecting_write(struct selector_key *key) {
    int error;
    socklen_t len = sizeof(error);
    struct request_st *d = &ATTACHMENT(key)->client_request;

    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        d->status = socks_status_general_SOCKS_server_failure;
    } else {
        if (error == 0) {
            d->status = socks_status_succeeded;
            ATTACHMENT(key)->server_fd = key->fd;
        } else {
            d->status = errno_to_socks(error);
        }
    }

    selector_status s = 0;
    s |= selector_set_interest(key->s, *d->client_fd, OP_WRITE);
    s |= selector_set_interest(key->s, *d->server_fd, OP_NOOP);
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

    if (configuration.socks5.sniffers_enabled) {
        pop3_credentials_init(&ATTACHMENT(key)->client_sniffers.pop3_data.credentials);
        ATTACHMENT(key)->client_sniffers.pop3_data.parser = pop3_sniffer_init();
        if (ATTACHMENT(key)->client_sniffers.pop3_data.parser == NULL && logger != NULL) {
            logger_append_to_log(
                    logger,
                    log_severity_error,
                    "No se pudo crear el parser del sniffer pop3",
                    0);
        }

        http_sniffer_init(&ATTACHMENT(key)->client_sniffers.http_credentials);
        if (ATTACHMENT(key)->client_sniffers.http_credentials.parser == NULL && logger != NULL) {
            logger_append_to_log(
                    logger,
                    log_severity_error,
                    "No se pudo crear el parser del sniffer http",
                    0);
        }
    } else {
        ATTACHMENT(key)->client_sniffers.done = true;
    }
}

/** lee bytes de un socket y los encola para ser escritos en otro */
static unsigned copy_read(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);

    struct copy *d = copy_ptr(key);

    assert(*d->fd == key->fd);
    size_t size;
    ssize_t n;
    unsigned ret = COPY;

    uint8_t *ptr = buffer_write_ptr(d->read_buffer, &size);
    n = recv(key->fd, ptr, size, 0);
    if (n <= 0) {
        shutdown(*d->fd, SHUT_RD);
        d->duplex &= ~OP_READ;
        if (*d->other->fd != -1) {
            shutdown(*d->other->fd, SHUT_WR);
            d->other->duplex &= ~OP_WRITE;
        }
    } else {
        /** Esto quiere decir que estamos leyendo una request */
        if (*d->fd == s->client_fd && !s->client_sniffers.done) {
            /** El parser del http termina ante input invalido, el del pop3 no */
            if (!s->client_sniffers.http_credentials.finished) {
                http_sniffer_consume(ptr, n, &s->client_sniffers.http_credentials);
            }

            if (s->client_sniffers.http_credentials.finished && s->client_sniffers.http_credentials.error == HTTP_SNIFFER_NO_ERROR) {
                s->client_sniffers.done = true;

                struct sniffed_credentials *credentials = malloc(sizeof(*credentials));
                if (credentials != NULL) {
                    credentials->datetime = logger_get_datetime();
                    if (credentials->datetime == NULL)
                        goto cont;

                    uint32_t len = strlen(s->client_sniffers.http_credentials.user);
                    credentials->username = malloc(sizeof(*credentials->username) * (len + 1));
                    if (credentials->username == NULL) {
                        free(credentials->datetime);
                        free(credentials);
                        goto cont;
                    }
                    memcpy(credentials->username, s->client_sniffers.http_credentials.user, len + 1);

                    len = strlen(s->client_sniffers.http_credentials.password);
                    credentials->password = malloc(sizeof(*credentials->password) * (len + 1));
                    if (credentials->password == NULL) {
                        free(credentials->datetime);
                        free(credentials->username);
                        free(credentials);
                        goto cont;
                    }
                    memcpy(credentials->password, s->client_sniffers.http_credentials.password, len + 1);

                    credentials->logger_user = malloc(sizeof(*credentials->logger_user) * (s->credentials.username_length + 1));
                    if (credentials->logger_user == NULL) {
                        free(credentials->datetime);
                        free(credentials->username);
                        free(credentials->password);
                        free(credentials);
                        goto cont;
                    }
                    memcpy(credentials->logger_user, s->credentials.username, s->credentials.username_length + 1);

                    uint16_t p;
                    extract_ip_port_(&s->client_addr, credentials->destination, &p);

                    if (s->client_addr.ss_family == AF_INET) {
                        snprintf(credentials->port, PORT_DIGITS, "%d", ((struct sockaddr_in*)&s->client_addr)->sin_port);
                    } else {
                        snprintf(credentials->port, PORT_DIGITS, "%d", ((struct sockaddr_in6*)&s->client_addr)->sin6_port);
                    }
                    credentials->port[PORT_DIGITS] = '\0';

                    credentials->protocol = HTTP_PROTOCOL;

                    sniffed_credentials_add(sniffed_credentials_l, credentials);
                }
                cont:;
            } else if (s->client_sniffers.http_credentials.error != HTTP_SNIFFER_REALLOC_ERROR) {
                pop3_sniffer_consume(
                        s->client_sniffers.pop3_data.parser,
                        &s->client_sniffers.pop3_data.credentials,
                        ptr,
                        n);
                if (s->client_sniffers.pop3_data.credentials.finished) {
                    struct sniffed_credentials *credentials = malloc(sizeof(*credentials));
                    if (credentials != NULL) {
                        credentials->datetime = logger_get_datetime();
                        if (credentials->datetime == NULL)
                            goto cont;

                        uint32_t len = s->client_sniffers.pop3_data.credentials.user_length;
                        credentials->username = malloc(sizeof(*credentials->username) * (len + 1));
                        if (credentials->username == NULL) {
                            free(credentials->datetime);
                            free(credentials);
                            goto cont;
                        }
                        memcpy(credentials->username, s->client_sniffers.pop3_data.credentials.user, len + 1);

                        len = s->client_sniffers.pop3_data.credentials.password_length;
                        credentials->password = malloc(sizeof(*credentials->password) * (len + 1));
                        if (credentials->password == NULL) {
                            free(credentials->datetime);
                            free(credentials->username);
                            free(credentials);
                            goto cont;
                        }
                        memcpy(credentials->password, s->client_sniffers.pop3_data.credentials.password, len + 1);

                        credentials->logger_user = malloc(sizeof(*credentials->logger_user) * (s->credentials.username_length + 1));
                        if (credentials->logger_user == NULL) {
                            free(credentials->datetime);
                            free(credentials->username);
                            free(credentials->password);
                            free(credentials);
                            goto cont;
                        }
                        memcpy(credentials->logger_user, s->credentials.username, s->credentials.username_length + 1);

                        uint16_t p;
                        extract_ip_port_(&s->client_addr, credentials->destination, &p);

                        if (s->client_addr.ss_family == AF_INET) {
                            snprintf(credentials->port, PORT_DIGITS, "%d", ((struct sockaddr_in*)&s->client_addr)->sin_port);
                        } else {
                            snprintf(credentials->port, PORT_DIGITS, "%d", ((struct sockaddr_in6*)&s->client_addr)->sin6_port);
                        }
                        credentials->port[PORT_DIGITS] = '\0';

                        credentials->protocol = POP3_PROTOCOL;

                        sniffed_credentials_add(sniffed_credentials_l, credentials);
                    }
                }
            }
        }

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
        if (*d->fd == ATTACHMENT(key)->client_fd) {
            ATTACHMENT(key)->bytes_downloaded += n;
        } else {
            ATTACHMENT(key)->bytes_uploaded += n;
        }
        bytes_transferred += n;
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
