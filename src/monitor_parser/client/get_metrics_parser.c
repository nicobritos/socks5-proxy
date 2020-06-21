#include <stdio.h>
#include <stdlib.h>

#include "../../utils/parser.h"
#include "get_metrics_parser.h"

#define CHUNK_SIZE 10

/* Funciones auxiliares */
void *resize_if_needed(void *ptr, size_t ptr_size, size_t current_length);

struct metrics *error(struct metrics *ans, get_metrics_parser_error_t error_type);

// definición de maquina

enum states {
    ST_ECON_1,
    ST_ECON_2,
    ST_ECON_3,
    ST_ECON_4,
    ST_ACON_1,
    ST_ACON_2,
    ST_ACON_3,
    ST_ACON_4,
    ST_BYTES_1,
    ST_BYTES_2,
    ST_BYTES_3,
    ST_BYTES_4,
    ST_END,
    ST_INVALID_INPUT_FORMAT,
};

enum event_type {
    SUCCESS,
    COPY_ECON,
    COPY_ACON,
    COPY_BYTES,
    END_T,
    INVALID_INPUT_FORMAT_T,
};

static void
next_state(struct parser_event *ret, const uint8_t c) {
    ret->type = SUCCESS;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_econ(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_ECON;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_acon(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_ACON;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_bytes(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_BYTES;
    ret->n = 1;
    ret->data[0] = c;
}

static void
end(struct parser_event *ret, const uint8_t c) {
    ret->type = END_T;
    ret->n = 1;
    ret->data[0] = c;
}

static void
invalid_input(struct parser_event *ret, const uint8_t c) {
    ret->type = INVALID_INPUT_FORMAT_T;
    ret->n = 1;
    ret->data[0] = c;
}

static const struct parser_state_transition ECON_1[] = {
    {.when = ANY, .dest = ST_ECON_2, .act1 = copy_econ,},
};

static const struct parser_state_transition ECON_2[] = {
    {.when = ANY, .dest = ST_ECON_3, .act1 = copy_econ,},
};

static const struct parser_state_transition ECON_3[] = {
    {.when = ANY, .dest = ST_ECON_4, .act1 = copy_econ,},
};

static const struct parser_state_transition ECON_4[] = {
    {.when = ANY, .dest = ST_ACON_1, .act1 = copy_econ,},
};

static const struct parser_state_transition ACON_1[] = {
    {.when = ANY, .dest = ST_ACON_2, .act1 = copy_acon,},
};

static const struct parser_state_transition ACON_2[] = {
    {.when = ANY, .dest = ST_ACON_3, .act1 = copy_acon,},
};

static const struct parser_state_transition ACON_3[] = {
    {.when = ANY, .dest = ST_ACON_4, .act1 = copy_acon,},
};

static const struct parser_state_transition ACON_4[] = {
    {.when = ANY, .dest = ST_BYTES_1, .act1 = copy_acon,},
};

static const struct parser_state_transition BYTES_1[] = {
    {.when = ANY, .dest = ST_BYTES_2, .act1 = copy_bytes,},
};

static const struct parser_state_transition BYTES_2[] = {
    {.when = ANY, .dest = ST_BYTES_3, .act1 = copy_bytes,},
};

static const struct parser_state_transition BYTES_3[] = {
    {.when = ANY, .dest = ST_BYTES_4, .act1 = copy_bytes,},
};

static const struct parser_state_transition BYTES_4[] = {
    {.when = ANY, .dest = ST_END, .act1 = end,},
};

static const struct parser_state_transition END[] = {
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition INVALID_INPUT_FORMAT[] = {
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition *states[] = {
    ECON_1,
    ECON_2,
    ECON_3,
    ECON_4,
    ACON_1,
    ACON_2,
    ACON_3,
    ACON_4,
    BYTES_1,
    BYTES_2,
    BYTES_3,
    BYTES_4,
    END,
    INVALID_INPUT_FORMAT,
};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t states_n[] = {
    N(ECON_1),
    N(ECON_2),
    N(ECON_3),
    N(ECON_4),
    N(ACON_1),
    N(ACON_2),
    N(ACON_3),
    N(ACON_4),
    N(BYTES_1),
    N(BYTES_2),
    N(BYTES_3),
    N(BYTES_4),
    N(END),
    N(INVALID_INPUT_FORMAT),
};

static struct parser_definition definition = {
        .states_count = N(states),
        .states       = states,
        .states_n     = states_n,
        .start_state  = ST_ECON_1,
};

struct metrics * get_metrics_parser(uint8_t *s, size_t length) {
    struct metrics * ans = calloc(1, sizeof(*ans));
    struct parser *parser = parser_init(parser_no_classes(), &definition);
    int finished = 0;
    for (size_t i = 0; i<length; i++) {
        const struct parser_event* ret = parser_feed(parser, s[i]);
        switch (ret->type) {
            case COPY_ECON:
                ans->established_cons *= 256;
                ans->established_cons += s[i];
            break;
            case COPY_ACON:
                ans->actual_cons *= 256;
                ans->actual_cons += s[i];
            break;
            case COPY_BYTES:
                ans->bytes_transferred *= 256;
                ans->bytes_transferred += s[i];
            break;
            case END_T:
                ans->bytes_transferred *= 256;
                ans->bytes_transferred += s[i];
                finished = 1;
            break;
            case INVALID_INPUT_FORMAT_T:
                parser_destroy(parser);
                return error(ans, INVALID_INPUT_FORMAT_ERROR);
        }
    }
    if(!finished){
        parser_destroy(parser);
        return error(ans, INVALID_INPUT_FORMAT_ERROR);
    }
    parser_destroy(parser);
    return ans;
}

void free_metrics(struct metrics *metrics) {
    if (metrics != NULL) {
        free(metrics);
    }
}

struct metrics *error(struct metrics *ans, get_metrics_parser_error_t error_type) {
    free_metrics(ans);
    ans = calloc(1, sizeof(*ans));
    ans->error = error_type;
    return ans;
}

void *resize_if_needed(void *ptr, size_t ptr_size, size_t current_length) {
    if (current_length % CHUNK_SIZE == 0) {
        return realloc(ptr, ptr_size * (current_length + CHUNK_SIZE));
    }
    return ptr;
}

/** 
 * To test with afl-fuzz uncomment the main function below and run:
 *     1. Create a directory for example inputs (i.e. parser_test_case)
 *     2. Insert at least 1 (one) example file in the created directory
 *     3. Run in the terminal "afl-clang get_metrics_parser.c parser.c -o get_metrics_parser -pedantic -std=c99" (or afl-gcc)
 *     4. Run in the terminal "afl-fuzz -i parser_test_case -o afl-output -- ./get_metrics_parser @@"
 */

/*
int main(int argc, char ** argv){
    FILE * fp;
    int16_t c;
    int size = 1000;
    uint8_t *buffer = calloc(1,size * sizeof(*buffer));
    if(buffer == NULL){
        return 1;
    }
    if(argc != 2){
        return 1;
    }
    fp = fopen(argv[1], "r");
    int i = 0;
    while((c=fgetc(fp)) != EOF){
        if(i == size){
            size += size;
            buffer = realloc(buffer, size * sizeof(*buffer));
            if(buffer == NULL){
                return 1;
            }
        }
        buffer[i] = c;
        i++;
    }
    buffer = realloc(buffer, i * sizeof(*buffer));
    fclose(fp);

    struct metrics * ans = get_metrics_parser(buffer, i);
    free(buffer);
    if(ans->error != NO_ERROR){
        printf("error\n");
    } else {
        printf("%u\n", ans->established_cons);
        printf("%u\n", ans->actual_cons);
        printf("%u\n", ans->bytes_transferred);
    }
    free_metrics(ans);
    return 0;
}
*/