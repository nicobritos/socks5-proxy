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
