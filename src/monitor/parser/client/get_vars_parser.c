#include <stdio.h>
#include <stdlib.h>

#include "../../../utils/parser.h"
#include "get_vars_parser.h"

#define CHUNK_SIZE 10

/* Funciones auxiliares */
void *resize_if_needed(void *ptr, size_t ptr_size, size_t current_length);

struct vars *error(struct vars *ans, parser_error_t error_type);

// definición de maquina

enum states {
    ST_VCODE,
    ST_IO_TIMEOUT_VALUE,
    ST_LMODE_VALUE,
    ST_LMODE_END,
    ST_END,
    ST_INVALID_INPUT_FORMAT,
};

enum event_type {
    SUCCESS,
    COPY_IO_TIMEOUT,
    COPY_LMODE,
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
copy_io_timeout(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_IO_TIMEOUT;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_lmode(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_LMODE;
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

static const struct parser_state_transition VCODE[] = {
    {.when = '\0', .dest = ST_END, .act1 = end,},
    {.when = '\1', .dest = ST_IO_TIMEOUT_VALUE, .act1 = next_state,},
    {.when = '\2', .dest = ST_LMODE_VALUE, .act1 = next_state,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition IO_TIMEOUT_VALUE[] = {
    {.when = '\0', .dest = ST_VCODE, .act1 = next_state,},
    {.when = '0', .dest = ST_IO_TIMEOUT_VALUE, .act1 = copy_io_timeout,},
    {.when = '1', .dest = ST_IO_TIMEOUT_VALUE, .act1 = copy_io_timeout,},
    {.when = '2', .dest = ST_IO_TIMEOUT_VALUE, .act1 = copy_io_timeout,},
    {.when = '3', .dest = ST_IO_TIMEOUT_VALUE, .act1 = copy_io_timeout,},
    {.when = '4', .dest = ST_IO_TIMEOUT_VALUE, .act1 = copy_io_timeout,},
    {.when = '5', .dest = ST_IO_TIMEOUT_VALUE, .act1 = copy_io_timeout,},
    {.when = '6', .dest = ST_IO_TIMEOUT_VALUE, .act1 = copy_io_timeout,},
    {.when = '7', .dest = ST_IO_TIMEOUT_VALUE, .act1 = copy_io_timeout,},
    {.when = '8', .dest = ST_IO_TIMEOUT_VALUE, .act1 = copy_io_timeout,},
    {.when = '9', .dest = ST_IO_TIMEOUT_VALUE, .act1 = copy_io_timeout,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition LMODE_VALUE[] = {
    {.when = '\0', .dest = ST_VCODE, .act1 = next_state,},
    {.when = '1', .dest = ST_LMODE_END, .act1 = copy_lmode,},
    {.when = '2', .dest = ST_LMODE_END, .act1 = copy_lmode,},
    {.when = '3', .dest = ST_LMODE_END, .act1 = copy_lmode,},
    {.when = '4', .dest = ST_LMODE_END, .act1 = copy_lmode,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition LMODE_END[] = {
    {.when = '\0', .dest = ST_VCODE, .act1 = next_state,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition END[] = {
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition INVALID_INPUT_FORMAT[] = {
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition *states[] = {
    VCODE,
    IO_TIMEOUT_VALUE,
    LMODE_VALUE,
    LMODE_END,
    END,
    INVALID_INPUT_FORMAT,
};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t states_n[] = {
    N(VCODE),
    N(IO_TIMEOUT_VALUE),
    N(LMODE_VALUE),
    N(LMODE_END),
    N(END),
    N(INVALID_INPUT_FORMAT),
};

static struct parser_definition definition = {
        .states_count = N(states),
        .states       = states,
        .states_n     = states_n,
        .start_state  = ST_VCODE,
};

struct vars * get_vars_parser(uint8_t *s, size_t length) {
    struct vars * ans = calloc(1, sizeof(*ans));
    struct parser *parser = parser_init(parser_no_classes(), &definition);
    size_t message_length = 0;
    int finished = 0;
    for (size_t i = 0; i<length; i++) {
        const struct parser_event* ret = parser_feed(parser, s[i]);
        switch (ret->type) {
            case COPY_IO_TIMEOUT:
                ans->io_timeout *= 10;
                ans->io_timeout += s[i] - '0';
            break;
            case COPY_LMODE:
                ans->lmode += s[i] - '0';
            break;
            case END_T:
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

void free_vars(struct vars *vars) {
    if (vars != NULL) {
        free(vars);
    }
}

struct vars *error(struct vars *ans, parser_error_t error_type) {
    free_vars(ans);
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
 *     3. Run in the terminal "afl-clang auth_server_response_parser.c parser.c -o auth_server_response_parser -pedantic -std=c99" (or afl-gcc)
 *     4. Run in the terminal "afl-fuzz -i parser_test_case -o afl-output -- ./auth_server_response_parser @@"
 */


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

    struct vars * ans = get_vars_parser(buffer, i);
    free(buffer);
    if(ans->error != NO_ERROR){
        printf("error\n");
    } else {
        printf("IO Timeout = %zu\n", ans->io_timeout);
        printf("Logger Severity = %u\n", ans->lmode);
    }
    free_vars(ans);
    return 0;
}
