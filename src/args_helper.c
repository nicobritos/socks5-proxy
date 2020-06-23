#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <limits.h>    /* LONG_MIN et al */
#include <string.h>    /* memset */
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdbool.h>

#include "args_helper.h"
#include "socks5/message/auth_user_pass_helper.h"
#include "configuration.h"
#include "utils/log_helper.h"

#define MAX_USERS 10
#define IPV6_LENGTH 16

static log_t system_log = NULL;

static unsigned short
port(const char *s) {
    char *end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 0 || sl > USHRT_MAX) {
        fprintf(stderr, "Port not in range [1-65536]: %s\n", s);
        if (system_log != NULL) {
            logger_append_to_log(system_log, log_severity_error, "Port not in range [1-65536]: %s", 1, s);
        }
        exit(1);
        return 1;
    }
    return htons(sl);
}

static void
user(char *s) {
    char *p = strchr(s, ':');
    struct auth_user_pass_credentials credentials;

    if (p == NULL) {
        fprintf(stderr, "password not found\n");
        if (system_log != NULL) {
            logger_append_to_log(system_log, log_severity_error, "Invalid input: password not found", 0);
        }
        exit(1);
    } else {
        *p = 0;
        p++;
        credentials.username = s;
        credentials.username_length = p - s;
        credentials.password = p;
        auth_user_pass_helper_add(&credentials);
    }
}

static void
version(void) {
    fprintf(stderr, "socks5v version 0.0\n"
                    "ITBA Protocolos de Comunicación 2020/1 -- Grupo 6\n"
                    "Licencia MIT\n");
}

static void
usage(const char *progname) {
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h               Imprime la ayuda y termina.\n"
            "   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.\n"
            "   -L <conf  addr>  Dirección donde servirá el servicio de management.\n"
            "   -p <SOCKS port>  Puerto entrante conexiones SOCKS.\n"
            "   -P <conf port>   Puerto entrante conexiones configuracion\n"
            "   -u <name>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.\n"
            "   -v               Imprime información sobre la versión versión y termina.\n"
            "\n"
            "   --doh-ip    <ip>    \n"
            "   --doh-port  <port>  XXX\n"
            "   --doh-host  <host>  XXX\n"
            "   --doh-path  <host>  XXX\n"
            "   --doh-query <host>  XXX\n"

            "\n",
            progname);
    exit(1);
}

void
parse_args(const int argc, char **argv) {
    system_log = logger_get_system_log();
    logger_append_to_log(system_log, log_severity_debug, "prueba", 0);

    memset(&configuration, 0, sizeof(configuration));
    struct sockaddr_in6 *socks_in6 = (struct sockaddr_in6 *) &configuration.socks5.sockaddr;
    struct sockaddr_in6 *doh_in6 = (struct sockaddr_in6 *) &configuration.doh.sockaddr;
    struct sockaddr_in6 *monitor_in6 = (struct sockaddr_in6 *) &configuration.monitor.sockaddr;

    struct sockaddr_in *socks_in = (struct sockaddr_in *) &configuration.socks5.sockaddr;
    struct sockaddr_in *doh_in = (struct sockaddr_in *) &configuration.doh.sockaddr;
    struct sockaddr_in *monitor_in = (struct sockaddr_in *) &configuration.monitor.sockaddr;

    configuration.socks5.sockaddr.ss_family = DEFAULT_SOCKS_ADDR_FAMILY;
#if (DEFAULT_SOCKS_ADDR_FAMILY == AF_INET)
    socks_in->sin_addr.s_addr = DEFAULT_SOCKS_ADDR;
    socks_in->sin_port = htons(DEFAULT_SOCKS_PORT);
#elif (DEFAULT_SOCKS_ADDR_FAMILY == AF_INET6)
    socks_in6->sin6_addr = DEFAULT_SOCKS_ADDR;
    socks_in6->sin6_port = htons(DEFAULT_SOCKS_PORT);
#endif

    configuration.socks5.sniffers_enabled = DEFAULT_SOCKS_SNIFFER_ENABLED;
    configuration.socks5.socklen = sizeof(configuration.socks5.sockaddr);

    configuration.monitor.sockaddr.ss_family = DEFAULT_MONITOR_ADDR_FAMILY;
#if (DEFAULT_MONITOR_ADDR_FAMILY == AF_INET)
    monitor_in->sin_addr.s_addr = DEFAULT_MONITOR_ADDR;
    monitor_in->sin_port = htons(DEFAULT_MONITOR_PORT);
#elif (DEFAULT_MONITOR_ADDR_FAMILY == AF_INET6)
    monitor_in6->sin6_addr = DEFAULT_MONITOR_ADDR;
    monitor_in6->sin6_port = htons(DEFAULT_MONITOR_PORT);
#endif
    configuration.monitor.socklen = sizeof(configuration.monitor.sockaddr);

    configuration.doh.sockaddr.ss_family = DEFAULT_DOH_ADDR_FAMILY;
#if (DEFAULT_DOH_ADDR_FAMILY == AF_INET)
    doh_in->sin_addr.s_addr = DEFAULT_DOH_ADDR;
    doh_in->sin_port = htons(DEFAULT_DOH_PORT);
#elif (DEFAULT_DOH_ADDR_FAMILY == AF_INET6)
    doh_in6->sin6_addr = DEFAULT_DOH_ADDR;
    doh_in6->sin6_port = htons(DEFAULT_DOH_PORT);
#endif

    configuration.doh.domain_name = DEFAULT_DOH_DOMAIN;
    configuration.doh.socklen = sizeof(configuration.doh.sockaddr);

    int c;
    int nusers = 0;

    int address_ret;
    struct addrinfo hint, *res = NULL;
    memset(&hint, '\0', sizeof(hint));
    hint.ai_family = AF_UNSPEC; // No sabemos si lo que nos van a mandar es IPv4 o 6
    hint.ai_flags = AI_NUMERICHOST;

    while (true) {
        int option_index = 0;
        static struct option long_options[] = {
                {"doh-ip",    required_argument, 0, 0xD001},
                {"doh-port",  required_argument, 0, 0xD002},
                {"doh-host",  required_argument, 0, 0xD003},
                {"doh-path",  required_argument, 0, 0xD004},
                {"doh-query", required_argument, 0, 0xD005},
                {0, 0,                           0, 0}
        };

        c = getopt_long(argc, argv, "hl:L:Np:P:u:v", long_options, &option_index);
        if (c == EOF)
            break;

        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
            case 'l':
                address_ret = getaddrinfo(optarg, NULL, &hint, &res);
                if (address_ret != 0) {
                    freeaddrinfo(res);
                    fprintf(stderr, "Error parsing socks' IP '%s': %s\n", optarg,
                            strerror(address_ret == EAI_SYSTEM ? errno : address_ret));
                    if (system_log != NULL) {
                        logger_append_to_log(
                                system_log,
                                log_severity_error,
                                "Error parsing socks' IP '%s': %s",
                                2,
                                optarg,
                                strerror(address_ret == EAI_SYSTEM ? errno : address_ret));
                    }
                    exit(1);
                }
                if (socks_in->sin_family != res->ai_family) {
                    if (socks_in->sin_family == AF_INET) {
                        socks_in6->sin6_port = socks_in->sin_port;
                    } else {
                        socks_in->sin_port = socks_in6->sin6_port;
                    }
                    socks_in->sin_family = res->ai_family;
                }

                if (res->ai_family == AF_INET) {
                    socks_in->sin_addr.s_addr = ((struct sockaddr_in *) res->ai_addr)->sin_addr.s_addr;
                } else {
                    memcpy(&socks_in6->sin6_addr, &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr, IPV6_LENGTH);
                }
                freeaddrinfo(res);
                break;
            case 'L':
                address_ret = getaddrinfo(optarg, NULL, &hint, &res);
                if (address_ret != 0) {
                    freeaddrinfo(res);
                    fprintf(stderr, "Error parsing monitoring's IP '%s': %s\n", optarg,
                            strerror(address_ret == EAI_SYSTEM ? errno : address_ret));
                    if (system_log != NULL) {
                        logger_append_to_log(
                                system_log,
                                log_severity_error,
                                "Error parsing monitoring's IP '%s': %s",
                                2,
                                optarg,
                                strerror(address_ret == EAI_SYSTEM ? errno : address_ret));
                    }
                    exit(1);
                }
                if (monitor_in->sin_family != res->ai_family) {
                    if (monitor_in->sin_family == AF_INET) {
                        monitor_in6->sin6_port = monitor_in->sin_port;
                    } else {
                        monitor_in->sin_port = monitor_in6->sin6_port;
                    }
                    monitor_in->sin_family = res->ai_family;
                }

                if (res->ai_family == AF_INET) {
                    monitor_in->sin_addr.s_addr = ((struct sockaddr_in *) res->ai_addr)->sin_addr.s_addr;
                } else {
                    memcpy(&monitor_in6->sin6_addr, &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr, IPV6_LENGTH);
                }
                freeaddrinfo(res);
                break;
            case 'N':
                configuration.socks5.sniffers_enabled = false;
                break;
            case 'p':
                if (socks_in->sin_family == AF_INET) {
                    socks_in->sin_port = port(optarg);
                } else {
                    socks_in6->sin6_port = port(optarg);
                }
                break;
            case 'P':
                if (monitor_in->sin_family == AF_INET) {
                    monitor_in->sin_port = port(optarg);
                } else {
                    monitor_in6->sin6_port = port(optarg);
                }
                break;
            case 'u':
                if (nusers >= MAX_USERS) {
                    fprintf(stderr, "Too much command line-specified users\n");
                    if (system_log != NULL) {
                        logger_append_to_log(
                                system_log,
                                log_severity_error,
                                "Too much command line-specified users",
                                0);
                    }
                    exit(1);
                } else {
                    user(optarg);
                    nusers++;
                }
                break;
            case 'v':
                version();
                exit(0);
            case 0xD001:
                address_ret = getaddrinfo(optarg, NULL, &hint, &res);
                if (address_ret != 0) {
                    freeaddrinfo(res);
                    fprintf(stderr, "Error parsing doh's IP '%s': %s\n", optarg,
                            strerror(address_ret == EAI_SYSTEM ? errno : address_ret));
                    if (system_log != NULL) {
                        logger_append_to_log(
                                system_log,
                                log_severity_error,
                                "Error parsing doh's IP '%s': %s",
                                2,
                                optarg,
                                strerror(address_ret == EAI_SYSTEM ? errno : address_ret));
                    }
                    exit(1);
                }
                if (doh_in->sin_family != res->ai_family) {
                    if (doh_in->sin_family == AF_INET) {
                        doh_in6->sin6_port = doh_in->sin_port;
                    } else {
                        doh_in->sin_port = doh_in6->sin6_port;
                    }
                    doh_in->sin_family = res->ai_family;
                }

                if (res->ai_family == AF_INET) {
                    doh_in->sin_addr.s_addr = ((struct sockaddr_in *) res->ai_addr)->sin_addr.s_addr;
                } else {
                    memcpy(&doh_in6->sin6_addr, &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr, IPV6_LENGTH);
                }
                freeaddrinfo(res);
                break;
            case 0xD002:
                if (doh_in->sin_family == AF_INET) {
                    doh_in->sin_port = port(optarg);
                } else {
                    doh_in6->sin6_port = port(optarg);
                }
                break;
            case 0xD003:
                configuration.doh.domain_name = optarg;
                break;
            case 0xD004:
            case 0xD005:
                break;
            default:
                fprintf(stderr, "Unknown argument: %c\n", c);
                if (system_log != NULL) {
                    logger_append_to_log(
                            system_log,
                            log_severity_error,
                            "Unknown argument: %c",
                            1,
                            c);
                }
                exit(1);
        }
    }

    if (optind < argc) {
        fprintf(stderr, "There are invalid arguments\n");
        if (system_log != NULL) {
            logger_append_to_log(
                    system_log,
                    log_severity_error,
                    "There are invalid arguments",
                    0);
        }
        exit(1);
    }
}
