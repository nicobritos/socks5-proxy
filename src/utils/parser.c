#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "parser.h"

/* CDT del parser */
struct parser {
    /** tipificaciÃ³n para cada caracter */
    const unsigned     *classes;
    /** definiciÃ³n de estados */
    const struct parser_definition *def;
    /** Data adicional provista por el usuario */
    void *attachment;

    /* estado actual */
    unsigned            state;

    /* evento que se retorna */
    struct parser_event e1;
    /* evento que se retorna */
    struct parser_event e2;
};

void
parser_destroy(struct parser *p) {
    if(p != NULL) {
        free(p);
    }
}

struct parser *
parser_init(const unsigned *classes,
            const struct parser_definition *def) {
    struct parser *ret = malloc(sizeof(*ret));
    if(ret != NULL) {
        memset(ret, 0, sizeof(*ret));
        ret->classes = classes;
        ret->def     = def;
        ret->state   = def->start_state;
    }
    return ret;
}

void
parser_set_attachment(struct parser *p, void *attachment) {
    if (p != NULL)
        p->attachment = attachment;
}

void
parser_reset(struct parser *p) {
    p->state   = p->def->start_state;
}

const struct parser_event *
parser_feed(struct parser *p, const uint8_t c) {
    const unsigned type = p->classes[c];

    p->e1.next = p->e2.next = 0;

    const struct parser_state_transition *state = p->def->states[p->state];
    const size_t n                              = p->def->states_n[p->state];
    bool matched   = false;

    for(unsigned i = 0; i < n ; i++) {
        const int when = state[i].when;
        if (state[i].when <= 0xFF) {
            matched = (c == when);
        } else if(state[i].when == (int) ANY) {
            matched = true;
        } else if(state[i].when > 0xFF) {
            matched = (type & when);
        } else {
            matched = false;
        }

        if(matched) {
            unsigned dest;

            if (state[i].dest_f != NULL) {
                dest = state[i].dest_f(p->attachment, c);
            } else {
                dest = state[i].dest;
            }

            state[i].act1(&p->e1, c);
            if(state[i].act2 != NULL) {
                p->e1.next = &p->e2;
                state[i].act2(&p->e2, c);
            }

            p->state = dest;
            break;
        }
    }
    return &p->e1;
}

/**
 * 0xFF es solo 255 elementos, con un uint8_t podemos
 * referenciar 256 elementos
 */
static const unsigned classes[0xFF + 1] = {0x00};

const unsigned *
parser_no_classes(void) {
    return classes;
}
