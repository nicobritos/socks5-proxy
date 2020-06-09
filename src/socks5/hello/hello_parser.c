/**
 * request.c -- parser del hello de SOCKS5
 */
#include <stdio.h>
#include <stdlib.h>

#include "hello_parser.h"

void hello_parser_init(struct hello_parser *p) {
    p->state = hello_version;
    p->remaining = 0;
}

enum hello_state hello_parser_feed(struct hello_parser *p, const uint8_t b) {
    switch (p->state) {
        case hello_version:
            if (b == 0x05) {
                p->state = hello_nmethods;
            } else {
                p->state = hello_error_unsupported_version;
            }
            break;
        case hello_nmethods:
            p->remaining = b;
            p->state = hello_methods;

            if (p->remaining <= 0) {
                p->state = hello_done;
            }
            break;
        case hello_methods:
            if (p->on_authentication_method != NULL) {
                p->on_authentication_method(p, b);
            }
            p->remaining--;
            if (p->remaining <= 0) {
                p->state = hello_done;
            }
            break;
        case hello_done:
        case hello_error_unsupported_version:
            // nada que hacer, nos quedamos en este estado
            break;
        default:
            fprintf(stderr, "unknown hello_state %d\n", p->state);
            abort();
    }

    return p->state;
}

bool hello_is_done(const enum hello_state state, bool *errored) {
    switch (state) {
        case hello_error_unsupported_version:
            if (errored != NULL) *errored = true;
            /* no break */
        case hello_done:
            return true;
        default:
            return false;
    }
}

const char *hello_error(const struct hello_parser *p) {
    return p->state == hello_error_unsupported_version ? "unsupported version" : "";
}

void hello_parser_close(struct hello_parser *p) {
    /* no hay nada que liberar */
}

enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *errored) {
    enum hello_state st = p->state;

    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = hello_parser_feed(p, c);
        if (hello_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

int hello_marshall(buffer *b, const uint8_t method) {
    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if (n < 2) {
        return -1;
    }
    buff[0] = 0x05;
    buff[1] = method;
    buffer_write_adv(b, 2);
    return 2;
}