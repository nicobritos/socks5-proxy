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
            uint8_t packet_index;
            uint16_t str_index;
        } access_log;
        struct {
            sorted_hashmap_list_t list;
            sorted_hashmap_list_node_t current_node;
            uint8_t packet_index;
            uint16_t str_index;
        } users;
        struct {
            sniffed_credentials_list list;
            sniffed_credentials_node current_node;
            uint8_t packet_index;
            uint16_t str_index;
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
static bool read_process(const monitor_t m);
static void write_response(const monitor_t m);

/** ---------------- WRITE ---------------- */
static void write_init(unsigned state, struct selector_key *key);
static unsigned write_do(struct selector_key *key);
static void write_close(unsigned state, struct selector_key *key);

/** ---------------- AUX ---------------- */
static bool write_data(monitor_t m);

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
//    parser_init(&d->parser);
    ATTACHMENT(key)->sent = false;
}

static unsigned read_do(struct selector_key *key) {
    monitor_t m = ATTACHMENT(key);
    unsigned ret = READ;
    bool error = false;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(&m->read_buffer, &count);
    n = sctp_recvmsg(key->fd, ptr, count, (struct sockaddr *) NULL, 0, &m->sndrcvinfo, 0);
    if (n > 0) {
        buffer_write_adv(&m->read_buffer, n);
        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
            m->command = command_request_parser(ptr, n);
            ret = WRITE;
        } else {
            ret = ERROR;
        }
        // TODO: Chunks y chequear errores
//        parser_consume(d->read_buffer, &d->parser, &error);
//        if (hello_is_done(st, NULL)) {
//            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
//            } else {
//                ret = ERROR;
//            }
//        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

static void read_close(unsigned state, struct selector_key *key) {

}

static bool read_process(const monitor_t m) {
    switch (m->command->code) {
        case GET_ACCESS_LOG:
        case GET_METRICS:
            break;
        case GET_PASSWORDS: {
            if (m->command_data.users.current_node == NULL)
                return READ;

            m->command_data.passwords.list = sniffed_credentials_create_list();
            if (m->command_data.passwords.list != NULL) {
                m->command_data.passwords.current_node = sniffed_credentials_get_first(socks_get_sniffed_credentials_list());
                struct sniffed_credentials *credentials = sniffed_credentials_get(m->command_data.passwords.current_node);

                sniffed_credentials_node next = sniffed_credentials_get_next(m->command_data.passwords.current_node);
                size_t n;
                uint8_t *b = buffer_write_ptr(&m->write_buffer, &n);
                uint16_t written = 0;
                // Aca escribir la rta (NO HACER FREE DE LA LISTA)
            }
            return WRITE;
        }
        case GET_USERS: {
            if (m->command_data.users.current_node == NULL)
                return READ;

            m->command_data.users.list = auth_user_pass_get_values();
            if (m->command_data.users.list != NULL) {
                m->command_data.users.current_node = sorted_hashmap_list_get_first(m->command_data.users.list);
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
            return WRITE;
        }
        case GET_VARS: {
            if (m->sent)
                return READ;

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
            return WRITE;
        }
        case SET_USER:
            break;
        case SET_VAR:
            break;
    }


    if (write_response(m->write_buffer, m) == -1) {
        ret = ERROR;
    }
    return ret;
}

/** ---------------- READ ---------------- */
static void write_init(unsigned state, struct selector_key *key) {
//    parser_init(&d->parser);
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
            if (read_process(m)) {
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



static bool authenticate_user(char *buffer) {
    uint8_t userRec[MAX_BUFFER];
    uint8_t passRec[MAX_BUFFER];

    strcpy(userRec, buffer + 1);
    strcpy(passRec, buffer + 2 + strlen(userRec));

    if (strcmp(user, userRec) == 0) {
        if (strcmp(password, passRec) == 0) {
            logged = true;
        }
    }
    return logged;
}

static void sign_in(char *buffer) {
    uint8_t response[MAX_BUFFER];
    char message[255];
    bool userAuth = authenticate_user(buffer);
    if (userAuth) {
        printf("User:%s has signned in.\n", user);
        response[0] = 0x01;
        strcpy(message, "Welcome!");
    } else {
        printf("Failed authentication\n");
        response[0] = 0x00;
        strcpy(message, "Username Or Password Incorrect");
    }

    strcpy(response + 1, message);

    int ret = sctp_sendmsg(connSock, (void *) response, (size_t) sizeof(uint8_t) * (strlen(message) + 2), NULL, 0, 0, 0,
                           0, 0, 0);
    if (ret == -1) {
        printf("Error sending message\n");
    }
}

static void get_metrics() {

    /* RESPONSE
    +------+------+-------+
    | ECON | ACON | BYTES | 
    +------+------+-------+
    |   8  |   8  |   8   |  
    +------+------+-------+
    */

    const int RESPONSE_MAX_LENGTH = 24;
    uint8_t response[RESPONSE_MAX_LENGTH];

    // uint64_t tc = socks_get_total_connections();
    // uint64_t cc = socks_get_current_connections();
    // uint64_t tbt = sockes_get_total_bytes_transferred();

    // FALTA -> HACER LA CONVERSION DE uint64_t a uint8_t[8] Y AGREGARLOS AL RESPONSE;

    int ret = sctp_sendmsg(connSock, (void *) response, (size_t) sizeof(uint8_t) * RESPONSE_MAX_LENGTH, NULL, 0, 0, 0,
                           0, 0, 0);
    if (ret == -1) {
        printf("Error sending message\n");
    }
}

static void get_users() {

    /* RESPONSE
    +------------+------------+
    |    USER    |   STATUS   | 
    +------------+------------+
    |  Variable  |     1      |  
    +------------+------------+
    */

    const int RESPONSE_MAX_LENGTH = 1024;
    uint8_t response[RESPONSE_MAX_LENGTH];

    sorted_hashmap_list_t aup = auth_user_pass_get_values();
    if (aup != NULL) {
        int length = 0;
        sorted_hashmap_list_node_t node = sorted_hashmap_list_get_first(aup);
        while (node != NULL) {
            struct auth_user_pass_credentials *credentials = sorted_hashmap_list_get_element(node);
            strcpy(response + length, credentials->username);
            length += (credentials->username_length + 1);
            response[length] = credentials->active;
            length += 1;

            node = sorted_hashmap_list_get_next_node(node);
        }
        response[length] = '\0';
    }

    sorted_hashmap_list_free(aup);

    int ret = sctp_sendmsg(connSock, (void *) response, (size_t) sizeof(uint8_t) * RESPONSE_MAX_LENGTH, NULL, 0, 0, 0,
                           0, 0, 0);
    if (ret == -1) {
        printf("Error sending message\n");
    }

}

static void get_access_log() {

    /* RESPONSE
    +----------+----------+-------+----------+----------+----------+----------+----------+
    |   TIME   |   USER   | RTYPE |   OIP    |  OPORT   |   DEST   |  DPORT   |  STATUS  |
    +----------+----------+-------+----------+----------+----------+----------+----------+
    | Variable | Variable |   1   | Variable | Variable | Variable | Variable |    1     |
    +----------+----------+-------+----------+----------+----------+----------+----------+
    */


}

static void get_passwords() {
}

static void parse_command(char *buffer) {
    uint8_t code = buffer[0];
    switch (code) {
        case 0x01:
            get_metrics();
            break;
        case 0x02:
            printf("GET_USERS\n");
            get_users();
            break;
        case 0x03:
            printf("GET_ACCESS_LOG\n");
            get_access_log();
            break;
        case 0x04:
            printf("GET_PASSWORDS\n");
            get_passwords();
            break;
        case 0x05:
            printf("GET_VARS\n");
            get_vars();
            break;
        case 0x06:
            printf("SET_USER\n");
            // set_user();
            break;
        case 0x07:
            printf("SET_VAR\n");
            // set_var();
            break;
        default:
            break;
    }
}



int main2(int argc, char *argv[]) {
    while (1) {
        int ret = receive_request();
        if (ret > 0) {
            if (!logged) {
                sign_in(buffer);
            } else {
                parse_command(buffer);
            }
        } else {
            close(connSock);
        }
    }
    return 0;
}

