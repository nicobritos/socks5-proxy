//
// Created by Nacho Grasso on 07/06/2020.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <stdbool.h>
#include <netdb.h>
#include <limits.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>

#include "MonitorServer.h"
#include "parser/server/command_request_parser.h"
#include "../socks5/socks5nio.h"
#include "../socks5/sniffer/sniffed_credentials.h"
#include "../socks5/message/auth_user_pass_helper.h"
#include "../utils/log_helper.h"
#include "../utils/stm.h"
#include "../utils/buffer.h"

#define MAX_BUFFER 1024
#define MY_PORT_NUM 57611

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define ATTACHMENT(key) ( (struct monitor_t *)(key)->data)
#define VAR_SYSTEM_LOG 0x02
#define VAR_SOCKS_LOG 0x03
#define LOG_SEVERITY_ERROR 4
#define LOG_SEVERITY_WARNING 3
#define LOG_SEVERITY_INFO 2
#define LOG_SEVERITY_DEBUG 1

#define METRICS_RESPONSE_SIZE 24

/** maquina de estados general */
enum monitor_state {
    /**
     * recibe el mensaje del cliente y lo procesa
     *
     * Intereses:
     *   - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - READ   mientras el mensaje no este completo
     *   - WRITE  cuando ya procesamos el mensaje y podemos escribir
     *   - ERROR
     */
    READ,

    /**
     * Escribe la respuesta al cliente
     *
     * Intereses:
     *   - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - READ   cuando ya enviamos todo y la conexion siga abierta
     *   - WRITE  mientras quedan bytes por enviar
     *   - ERROR
     */
    WRITE,

    // estados terminales
    DONE,
    ERROR,
};

/**
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
typedef struct monitor_t {
    /** informacion del cliente */
    struct sockaddr_storage addr;
    struct sctp_sndrcvinfo sndrcvinfo;
    int fd;
    bool logged;
    bool sent;

    /** maquinas de estados */
    struct state_machine stm;
    struct command *command;

    union {
        struct {
            socks_access_log_node_t current_node;
        } access_log;
        struct {
            sorted_hashmap_list_t list;
            sorted_hashmap_list_node_t current_node;
        } users;
        struct {
            sniffed_credentials_node current_node;
        } passwords;
    } command_data;

    /** buffers para ser usados read_buffer, write_buffer */
    uint8_t raw_buff_a[8*1024], raw_buff_b[8 * 1024];
    buffer read_buffer, write_buffer;

    /** cantidad de referencias a este objecto. == 1 -> eliminar */
    uint32_t references;

    /** siguiente en pool */
    struct monitor_t *next;
} *monitor_t;


/**
 * Pool de struct monitor
 *
 * No hay race conditions porque hay un solo hilo
 */
static const uint32_t max_pool = 50;
static uint32_t pool_size = 0;
static monitor_t pool = NULL;

/** -------------------- DECLARATIONS --------------------- */
/** ---------------- MONITOR ---------------- */
static monitor_t monitor_new(int client_fd);
static const struct state_definition *monitor_describe_states();
static void monitor_destroy(monitor_t m);
static void monitor_destroy_(monitor_t m);

/**
 * Handlers monitor
 * Declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void monitor_read(struct selector_key *key);
static void monitor_write(struct selector_key *key);
static void monitor_close(struct selector_key *key);
static void monitor_done(struct selector_key* key);
static void close_fd_(int fd, struct selector_key* key);
static const struct fd_handler monitor_handler = {
        .handle_read   = monitor_read,
        .handle_write  = monitor_write,
        .handle_close  = monitor_close,
};

/** ---------------- READ ---------------- */
static void read_init(unsigned state, struct selector_key *key);
static unsigned read_do(struct selector_key *key);
static void read_close(unsigned state, struct selector_key *key);

/** ---------------- WRITE ---------------- */
static void write_init(unsigned state, struct selector_key *key);
static unsigned write_do(struct selector_key *key);
static void write_close(unsigned state, struct selector_key *key);

/** ---------------- AUX ---------------- */
static bool write_response_buffer(monitor_t const m);
static bool write_buffer_metrics(const monitor_t m);
static bool write_buffer_access_log(const monitor_t m);

static bool authenticate_user(char *buffer);
static void sign_in(char *buffer);
static void populate_vars(buffer *b, uint8_t logger_n, log_t logger);

/** ---------------- MONITOR HANDLERS ---------------- */
static const struct state_definition client_statbl[] = {
        {
                .state            = READ,
                .on_arrival       = read_init,
                .on_departure     = read_close,
                .on_read_ready    = read_do,
        }, {
                .state = WRITE,
                .on_arrival       = write_init,
                .on_departure     = write_close,
                .on_write_ready   = write_do,
        }, {
                .state = DONE,
        }, {
                .state = ERROR
        }
};


/** -------------------- DEFINITIONS --------------------- */
/** ---------------- MONITOR ---------------- */
/** ---------------- PUBLIC ---------------- */
/** Intenta aceptar la nueva conexión entrante*/
void monitor_passive_accept(struct selector_key *key) {
    monitor_t m;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    const int client = accept(key->fd, (struct sockaddr *) &client_addr, &client_addr_len);
    if (client == -1 || selector_fd_set_nio(client) == -1) goto fail;

    m = monitor_new(client);
    if (m == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }
    memcpy(&m->addr, &client_addr, client_addr_len);

    if (SELECTOR_SUCCESS != selector_register(key->s, client, &monitor_handler, OP_READ, m)) goto fail;
    return;

    fail:
    if (client != -1) close(client);
    monitor_destroy(m);
}

void monitor_pool_destroy() {
    monitor_t next, m;

    for (m = pool; m != NULL; m = next) {
        next = m->next;
        free(m);
    }

//    if (logger != NULL) {
//        logger_close_log(logger);
//        logger = NULL;
//    }
}

/** ---------------- PRIVATE ---------------- */
static monitor_t monitor_new(int client_fd) {
    monitor_t ret;

    if (pool == NULL) {
        ret = calloc(sizeof(*ret), 1);
        if (ret == NULL) return NULL;
    } else {
        ret = pool;
        pool = pool->next;
        ret->next = NULL;
        memset(ret, 0x00, sizeof(*ret));
    }

    ret->fd = client_fd;

    ret->stm.initial = READ;
    ret->stm.max_state = ERROR;
    ret->stm.states = monitor_describe_states();
    stm_init(&ret->stm);

    buffer_init(&ret->read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);

    ret->references = 1;

    return ret;
}

static const struct state_definition *monitor_describe_states() {
    return client_statbl;
}

/**
 * destruye un `monitor_t', tiene en cuenta las referencias  y el pool de objetos.
 */
static void monitor_destroy(monitor_t m) {
    if (m != NULL) {
        if (m->references == 1) {
            if (pool_size < max_pool) {
                m->next = pool;
                pool = m;
                pool_size++;
            } else {
                monitor_destroy_(m);
            }
        } else {
            m->references -= 1;
        }
    }
}

/** realmente destruye */
static void monitor_destroy_(monitor_t m) {
    free(m);
}

/**
 * Handlers monitpr
 * Handlers top level de la conexión pasiva.
 * son los que emiten los eventos a la maquina de estados.
 */
static void monitor_read(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum monitor_state st = stm_handler_read(stm, key);

    if (ERROR == st || DONE == st) {
        monitor_done(key);
    }
}

static void monitor_write(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum monitor_state st = stm_handler_write(stm, key);

    if (ERROR == st || DONE == st) {
        monitor_done(key);
    }
}

static void monitor_close(struct selector_key *key) {
    monitor_t m = ATTACHMENT(key);
    monitor_destroy(m);
}

static void monitor_done(struct selector_key* key) {
    /**
     * Cuando hacemos close_fd_ no sabemos si ya se libero el
     * socket, entonces nos guardamos las referencias. Si es 0
     * entonces ya fue liberado.
     */
    uint32_t references = ATTACHMENT(key)->references;
    if (ATTACHMENT(key)->fd != -1) {
        close_fd_(ATTACHMENT(key)->fd, key);
        references--;
        if (references == 0) return;
        ATTACHMENT(key)->fd = -1;
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

/** ---------------- READ ---------------- */
static void read_init(unsigned state, struct selector_key *key) {
    ATTACHMENT(key)->command = command_request_parser_init();
    ATTACHMENT(key)->sent = false;
}

static unsigned read_do(struct selector_key *key) {
    monitor_t m = ATTACHMENT(key);
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    if (m->command == NULL)
        return ERROR;
    ptr = buffer_write_ptr(&m->read_buffer, &count);
    n = sctp_recvmsg(key->fd, ptr, count, (struct sockaddr *) NULL, 0, &m->sndrcvinfo, 0);
    if (n > 0) {
        buffer_write_adv(&m->read_buffer, n);
        m->command = command_request_parser_consume(ptr, n, m->command);
        if (m->command == NULL)
            return ERROR;
        if (m->command->error != NO_ERROR)
            return ERROR;
        // Como los requests pesan poco supongo que llega entero
        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
            write_response_buffer(m);
            return WRITE;
        } else {
            return ERROR;
        }
    } else {
        return ERROR;
    }
}

static void read_close(unsigned state, struct selector_key *key) {
    if (ATTACHMENT(key)->command != NULL) {
        free_command(ATTACHMENT(key)->command);
        ATTACHMENT(key)->command = NULL;
    }
}

/** ---------------- WRITE ---------------- */
static void write_init(unsigned state, struct selector_key *key) {
//    parser_init(&d->parser);
}

/**
 * Devuelve true si hay datos para seguir escribiendo, false sino
 * @param m
 * @return
 */
static bool write_response_buffer(const monitor_t m) {
    switch (m->command->code) {
        case GET_METRICS:
            return write_buffer_metrics(m);
        case GET_ACCESS_LOG:
            return write_buffer_access_log(m);
        case GET_PASSWORDS: {
            if (m->sent && m->command_data.passwords.current_node == NULL)
                return false;

            if (m->command_data.passwords.current_node == NULL) {
                m->command_data.passwords.current_node = sniffed_credentials_get_first(
                        socks_get_sniffed_credentials_list());
                m->sent = true;
            }
            if (m->command_data.passwords.current_node != NULL) {
                struct sniffed_credentials *credentials = sniffed_credentials_get(m->command_data.passwords.current_node);

                sniffed_credentials_node next = sniffed_credentials_get_next(m->command_data.passwords.current_node);
                size_t n, i;
                char *b = buffer_write_ptr(&m->write_buffer, &n);

                i = sprintf(b, "%s", credentials->datetime);
                b[i++] = '\0';
                i += sprintf(b, "%s", credentials->username);
                b[i++] = '\0';
                i += sprintf(b, "P");
                b[i++] = '\0';
                i += sprintf(b, "%s", credentials->protocol);
                b[i++] = '\0';
                i += sprintf(b, "%s", credentials->destination);
                b[i++] = '\0';
                i += sprintf(b, "%s", credentials->port);
                b[i++] = '\0';
                i += sprintf(b, "%s", credentials->logger_user);
                b[i++] = '\0';
                i += sprintf(b, "%s", credentials->password);
                b[i++] = '\0';
                b[i++] = '\0';
                if (next == NULL)
                    b[i++] = '\0';

                buffer_write_adv(&m->write_buffer, i);

                m->command_data.passwords.current_node = next;
            }
            return true;
        }
        case GET_USERS: {
            if (m->sent && m->command_data.users.current_node == NULL)
                return false;

            if (m->command_data.passwords.current_node == NULL) {
                m->command_data.users.list = auth_user_pass_get_values();
                m->command_data.users.current_node = sorted_hashmap_list_get_first(m->command_data.users.list);
                m->sent = true;
            }
            if (m->command_data.users.list != NULL) {
                struct auth_user_pass_credentials *credentials = sorted_hashmap_list_get_element(m->command_data.users.current_node);

                sorted_hashmap_list_node_t next = sorted_hashmap_list_get_next_node(m->command_data.users.current_node);
                size_t n;
                uint8_t *b = buffer_write_ptr(&m->write_buffer, &n);
                buffer_write_adv(&m->write_buffer, credentials->username_length + (next != NULL ? 2 : 3));

                memcpy(b, credentials->username, credentials->username_length + 1);
                b[credentials->username_length + 1] = credentials->active ? 1 : 0;
                if (next == NULL) {
                    b[credentials->username_length + 2] = '\0';
                    sorted_hashmap_list_free(m->command_data.users.list);
                    m->command_data.users.list = NULL;
                    m->command_data.users.current_node = NULL;
                }
            }
            return true;
        }
        case GET_VARS: {
            if (m->sent)
                return false;

            uint8_t log_n;
            log_t log;

            switch (m->command->var) {
                case SYSTEM_LOG:
                    log = logger_get_system_log();
                    log_n = VAR_SYSTEM_LOG;
                    break;
                case SOCKS_LOG:
                    log = socks_get_log();
                    log_n = VAR_SOCKS_LOG;
                    break;
            }

            populate_vars(&m->write_buffer, log_n, log);
            m->sent = true;
            return true;
        }
        case SET_USER:
            break; // TODO
        case SET_VAR:
            break;
    }
}

static unsigned write_do(struct selector_key *key) {
    monitor_t m = ATTACHMENT(key);
    unsigned ret = WRITE;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_read_ptr(&m->write_buffer, &count);
    n = sctp_sendmsg(key->fd, (void *) ptr, (size_t) count, NULL, 0, 0, MSG_NOSIGNAL,0, 0, 0);
    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(&m->write_buffer, n);
        if (!buffer_can_read(&m->write_buffer)) {
            if (write_response_buffer(m)) {
                ret = WRITE;
            } else {
                if (selector_set_interest_key(key, OP_READ) == SELECTOR_SUCCESS) {
                    ret = READ;
                } else {
                    ret = ERROR;
                }
            }
        }
    }

    return ret;
}

static void write_close(unsigned state, struct selector_key *key) {
//    hello_parser_close(&d->parser);
}


/** ---------------- AUX ---------------- */
static bool write_buffer_metrics(const monitor_t m) {
    if (m->sent) return false;

    size_t n;
    uint8_t *buff = buffer_write_ptr(&m->write_buffer, &n);
    if (n < METRICS_RESPONSE_SIZE)
        return false;

    buffer_write_adv(&m->write_buffer, METRICS_RESPONSE_SIZE);

    uint8_t i = 0;
    uint8_t ib = 0;
    while (i < sizeof(uint64_t)) {
        buff[ib] = (socks_get_total_connections() >> ((sizeof(uint64_t) - i - 1) * 8)) & 0xFF;
        i++;
        ib++;
    }
    i = 0;
    while (i < sizeof(uint64_t)) {
        buff[ib] = (socks_get_current_connections() >> ((sizeof(uint64_t) - i - 1) * 8)) & 0xFF;
        i++;
        ib++;
    }
    i = 0;
    while (i < sizeof(uint64_t)) {
        buff[ib] = (socks_get_total_bytes_transferred() >> ((sizeof(uint64_t) - i - 1) * 8)) & 0xFF;
        i++;
        ib++;
    }

    return m->sent = true;
}

static bool write_buffer_access_log(const monitor_t m) {
    if (m->sent && m->command_data.access_log.current_node == NULL)
        return false;

    char *b;
    size_t n, i;
    if (m->command_data.access_log.current_node == NULL) {
        m->command_data.access_log.current_node = socks_get_first_access_log_node();
        if (m->command_data.access_log.current_node == NULL) {
            b = (char *) buffer_write_ptr(&m->write_buffer, &n);
            if (n < 2) // Necesitamos escribir un doble null (fin de entry, ver RFC)
                return false;

            b[0] = b[1] = '\0';
            buffer_write_adv(&m->write_buffer, i);
        }

        m->sent = true;
    }

    struct socks_access_log_details_t *details = socks_get_access_log(m->command_data.access_log.current_node);

    socks_access_log_node_t next = socks_get_next_access_log_node(m->command_data.access_log.current_node);
    b = (char *) buffer_write_ptr(&m->write_buffer, &n);

    // Tenemos que ver primero cuanto espacio necesitamos
    // Uso el caracter '.' como separador de strings, representa
    // el NULL en el RFC
    size_t space_needed = snprintf(
            NULL,
            0,
            "%s.%s.A.%s.%s.%s.%s.%s..",
            "");

    i = sprintf(b, "%s", details->datetime);
    b[i++] = '\0';
    i += sprintf(b, "%s", details->username);
    b[i++] = '\0';
    i += sprintf(b, "A");
    b[i++] = '\0';
    i += sprintf(b, "%s", details->origin.ip);
    b[i++] = '\0';
    i += sprintf(b, "%s", details->origin.port);
    b[i++] = '\0';
    i += sprintf(b, "%s", details->destination.name);
    b[i++] = '\0';
    i += sprintf(b, "%s", details->destination.port);
    b[i++] = '\0';
    i += sprintf(b, "%d", details->status);
    b[i++] = '\0';
    if (next == NULL)
        b[i++] = '\0';

    buffer_write_adv(&m->write_buffer, i);

    m->command_data.access_log.current_node = next;
    return true;
}





static bool authenticate_user(char *buffer) {

}

static void sign_in(char *buffer) {

}

static void populate_vars(buffer *b, uint8_t logger_n, log_t logger) {
    /*
    +-------+----------+
    | VCODE |  VVALUE  |
    +-------+----------+
    |   1   | Variable |
    +-------+----------+
    */

    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if (n < 3) {
        return;
    }
    buff[0] = logger_n;
    buffer_write_adv(b, 3);

    buff[0] = logger_n;
    enum log_severity log_sev = logger_get_log_severity(logger);
    switch (log_sev) {
        case log_severity_error:
            buff[1] = LOG_SEVERITY_ERROR + '0';
            break;
        case log_severity_warning:
            buff[1] = LOG_SEVERITY_WARNING + '0';
            break;
        case log_severity_debug:
            buff[1] = LOG_SEVERITY_DEBUG + '0';
            break;
        case log_severity_info:
            buff[1] = LOG_SEVERITY_INFO + '0';
            break;
    }
    buff[2] = '\0';
}




static char *user = "admin";
static char *password = "adminadmin";



//static bool authenticate_user(char *buffer) {
//    uint8_t userRec[MAX_BUFFER];
//    uint8_t passRec[MAX_BUFFER];
//
//    strcpy(userRec, buffer + 1);
//    strcpy(passRec, buffer + 2 + strlen(userRec));
//
//    if (strcmp(user, userRec) == 0) {
//        if (strcmp(password, passRec) == 0) {
//            logged = true;
//        }
//    }
//    return logged;
//}
//
//static void sign_in(char *buffer) {
//    uint8_t response[MAX_BUFFER];
//    char message[255];
//    bool userAuth = authenticate_user(buffer);
//    if (userAuth) {
//        printf("User:%s has signned in.\n", user);
//        response[0] = 0x01;
//        strcpy(message, "Welcome!");
//    } else {
//        printf("Failed authentication\n");
//        response[0] = 0x00;
//        strcpy(message, "Username Or Password Incorrect");
//    }
//
//    strcpy(response + 1, message);
//
//    int ret = sctp_sendmsg(connSock, (void *) response, (size_t) sizeof(uint8_t) * (strlen(message) + 2), NULL, 0, 0, 0,
//                           0, 0, 0);
//    if (ret == -1) {
//        printf("Error sending message\n");
//    }
//}
