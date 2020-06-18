#include "request.h"
#include <errno.h>

enum socks_response_status errno_to_socks(int e) {
    switch (e) {
        case EACCES:
        case EPERM:
            return socks_status_connection_not_allowed_by_ruleset;
        case EAFNOSUPPORT:
            return socks_status_address_type_not_supported;
        case ECONNREFUSED:
            return socks_status_connection_refused;
        case EPROTOTYPE:
            return socks_status_command_not_supported;
        case ETIMEDOUT:
            return socks_status_ttl_expired;
        case ENOTSOCK:
        case EISCONN:
        case EINTR:
        case EINPROGRESS:
        case EFAULT:
        case EBADF:
        case EALREADY:
        case EAGAIN:
        case EADDRINUSE:
        case EADDRNOTAVAIL:
        default:
            return socks_status_general_SOCKS_server_failure;
    }
}

/**
 * Devuelve un string que representa el estado del parser
 */
const char *socks_response_status_str(enum socks_response_status status) {
    switch (status) {
        case socks_status_succeeded:
            return "exitoso";
        case socks_status_general_SOCKS_server_failure:
            return "error: general del proxy";
        case socks_status_connection_not_allowed_by_ruleset:
            return "error: bloqueado por firewall";
        case socks_status_network_unreachable:
            return "error: no hay conexion a Internet";
        case socks_status_host_unreachable:
        case socks_status_connection_refused:
            return "error: no se pudo encontrar el servidor";
        case socks_status_ttl_expired:
            return "error: timeout";
        case socks_status_command_not_supported:
            return "error: comando no soportado";
        case socks_status_address_type_not_supported:
            return "error: tipo de address no soportado";
        default:
            return "desconocido";
    }
}
