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
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <limits.h>

#include "utils/selector.h"
#include "utils/log_helper.h"
#include "socks5/socks5nio.h"
#include "socks5/message/auth_user_pass_helper.h"

#define SYSTEM_LOG_FILENAME "system.log"

static bool done = false;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}

int
main(const int argc, const char **argv) {
    log_t system_log = init_system_log(SYSTEM_LOG_FILENAME, log_severity_debug);
    if (system_log == NULL) fprintf(stderr, "Couldn't initialize system_log");
    enum auth_user_pass_helper_status auth_status = auth_user_pass_helper_status_error_not_initialized;
    unsigned port = 1080;

    if (argc == 1) {
        // utilizamos el default
    } else if (argc == 2) {
        char *end = 0;
        const long sl = strtol(argv[1], &end, 10);

        if (end == argv[1] || '\0' != *end
            || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
            || sl < 0 || sl > USHRT_MAX) {
            fprintf(stderr, "Port should be an integer: %s\n", argv[1]);

            if (system_log != NULL) {
                append_to_log(system_log, log_severity_error, "Port should be an integer: %s", 1, argv[1]);
            }
            return 1;
        }
        port = sl;
    } else {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        if (system_log != NULL) {
            append_to_log(system_log, log_severity_error, "Usage: %s <port>", 1, argv[0]);
        }
        return 1;
    }

    // no tenemos nada que leer de stdin
    close(0);

    const char *err_msg = NULL;
    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    const int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server < 0) {
        err_msg = "Unable to create socket";
        goto finally;
    }

    fprintf(stdout, "Listening on TCP port %d\n", port);

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));

    if (bind(server, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
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
            .handle_read       = socksv5_passive_accept,
            .handle_write      = NULL,
            .handle_close      = NULL, // nada que liberar
    };
    ss = selector_register(selector, server, &socksv5,
                           OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }

    auth_status = auth_user_pass_helper_init();
    if (auth_status != auth_user_pass_helper_status_ok)
        fprintf(stderr, "Error initializing authentication module with code: %d\n", auth_status);
    if (system_log != NULL) {
        append_to_log(system_log, log_severity_info, "Server up with TCP port %d", 1, port);
    }
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
            append_to_log(system_log, log_severity_error, "%s: %s", 2,
                    (err_msg == NULL) ? "" : err_msg,
                    ss == SELECTOR_IO ? strerror(errno) : selector_error(ss)
            );
        }
        ret = 2;
    } else if (err_msg) {
        perror(err_msg);
        if (system_log != NULL) {
            append_to_log(system_log, log_severity_error, "%s: %s", 2, err_msg, strerror(errno));
        }
        ret = 1;
    }
    if (selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    socksv5_pool_destroy();
    if (system_log != NULL) {
        close_system_log();
        system_log = NULL;
    }

    if (auth_status == auth_user_pass_helper_status_ok) auth_user_pass_helper_close();
    if (server >= 0) close(server);
    return ret;
}
