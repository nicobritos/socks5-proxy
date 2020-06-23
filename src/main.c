/**
 * main.c - servidor proxy socks concurrente
 *
 * Interpreta los argumentos de línea de comandos, y monta un socket
 * pasivo.
 *
 * Todas las conexiones entrantes se manejarán en éste hilo.
 *
 * Se descargará en otro hilos las operaciones bloqueantes (resolución de
 * DNS utilizando getaddrinfo), pero toda esa complejidad está oculta en
 * el selector.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <unistd.h>
#include <sys/socket.h>  // socket
#include <netinet/in.h>

#include "args_helper.h"
#include "utils/selector.h"
#include "utils/log_helper.h"
#include "socks5/socks5nio.h"
#include "socks5/message/auth_user_pass_helper.h"
#include "configuration.h"

#define SYSTEM_LOG_FILENAME "system.log"

static bool done = false;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}

int
main(const int argc, char **argv) {
    log_t system_log = logger_init_system_log(SYSTEM_LOG_FILENAME, DEFAULT_LOG_LEVEL);
    if (system_log == NULL) fprintf(stderr, "Couldn't initialize system_log");

    enum auth_user_pass_helper_status auth_status = auth_user_pass_helper_init();
    if (auth_status != auth_user_pass_helper_status_ok)
        fprintf(stderr, "Error initializing authentication module with code: %d\n", auth_status);

    parse_args(argc, argv);

    // no tenemos nada que leer de stdin
    close(STDIN_FILENO);

    const char *err_msg = NULL;
    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;

    const int server = socket(configuration.socks5.sockaddr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (server < 0) {
        err_msg = "Unable to create socket";
        goto finally;
    }

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));
    // Necesitamos desactivar esto para bindear a IPv4 e IPv6 al mismo tiempo
    if (configuration.socks5.sockaddr.ss_family == AF_INET6) {
        setsockopt(server, IPPROTO_IPV6, IPV6_V6ONLY, &(int) {0}, sizeof(int));
    }

    if (bind(server, (struct sockaddr *) &configuration.socks5.sockaddr, sizeof(configuration.socks5.sockaddr)) < 0) {
        err_msg = "unable to bind socket";
        goto finally;
    }

    if (listen(server, 20) < 0) {
        err_msg = "unable to listen";
        goto finally;
    }

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);
    /** Algunos SOs ignoran el MSG_NOSIGNAL flag */
    signal(SIGPIPE, SIG_IGN);

    if (selector_fd_set_nio(server) == -1) {
        err_msg = "getting server socket flags";
        goto finally;
    }
    const struct selector_init conf = {
            .signal = SIGALRM,
            .select_timeout = {
                    .tv_sec  = 10,
                    .tv_nsec = 0,
            },
    };
    if (0 != selector_init(&conf)) {
        err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(1024);
    if (selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }
    const struct fd_handler socksv5 = {
            .handle_read       = socks_passive_accept,
            .handle_write      = NULL,
            .handle_close      = NULL, // nada que liberar
    };
    ss = selector_register(selector, server, &socksv5,
                           OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }


    if (configuration.socks5.sockaddr.ss_family == AF_INET) {
        uint16_t port = ntohs(((struct sockaddr_in *)&configuration.socks5.sockaddr)->sin_port);
        fprintf(stdout, "Listening on TCP port %d on IPv4 and IPv6\n", port);

        if (system_log != NULL) {
            logger_append_to_log(system_log, log_severity_info, "Server up with TCP port %d on IPv4 and IPv6", 1, port);
        }
    } else {
        uint16_t port = ntohs(((struct sockaddr_in6 *)&configuration.socks5.sockaddr)->sin6_port);
        fprintf(stdout, "Listening on TCP port %d on IPv6\n", port);

        if (system_log != NULL) {
            logger_append_to_log(system_log, log_severity_info, "Server up with TCP port %d on IPv6", 1, port);
        }
    }

    socks_init();
    for (; !done;) {
        err_msg = NULL;
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    }
    if (err_msg == NULL) {
        err_msg = "closing";
    }

    int ret = 0;
    finally:
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "" : err_msg,
                ss == SELECTOR_IO
                ? strerror(errno)
                : selector_error(ss));
        if (system_log != NULL) {
            logger_append_to_log(system_log, log_severity_error, "%s: %s", 2,
                                 (err_msg == NULL) ? "" : err_msg,
                                 ss == SELECTOR_IO ? strerror(errno) : selector_error(ss)
            );
        }
        ret = 2;
    } else if (err_msg) {
        perror(err_msg);
        if (system_log != NULL) {
            logger_append_to_log(system_log, log_severity_error, "%s: %s", 2, err_msg, strerror(errno));
        }
        ret = 1;
    }
    if (selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    socks_pool_destroy();
    if (system_log != NULL) {
        logger_close_system_log();
        system_log = NULL;
    }

    if (auth_status == auth_user_pass_helper_status_ok) auth_user_pass_helper_close();
    if (server >= 0) close(server);
    return ret;
}
