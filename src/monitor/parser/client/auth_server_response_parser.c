#include <stdio.h>
#include <stdlib.h>

#include "../../../utils/parser.h"
#include "auth_server_response_parser.h"

#define CHUNK_SIZE 10

/* Funciones auxiliares */
static void *resize_if_needed(void *ptr, size_t ptr_size, size_t current_length);

static struct auth_response *add_char_to_message(struct auth_response *ans, char c, size_t *message_current_length);

static struct auth_response *error(struct auth_response *ans, parser_error_t error_type);

// definición de maquina

enum states {
    ST_STATUS,
    ST_MESSAGE,
    ST_END,
    ST_INVALID_INPUT_FORMAT,
};

enum event_type {
    SUCCESS,
    COPY_STATUS,
    COPY_MESSAGE,
    END_T,
    INVALID_INPUT_FORMAT_T,
};

static void
copy_status(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_STATUS;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_message(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_MESSAGE;
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

static const struct parser_state_transition STATUS[] = {
    {.when = ANY, .dest = ST_MESSAGE, .act1 = copy_status,},
};

static const struct parser_state_transition MESSAGE[] = {
    {.when = '\0', .dest = ST_END, .act1 = end,},
    {.when = ANY, .dest = ST_MESSAGE, .act1 = copy_message,},
};

static const struct parser_state_transition END[] = {
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition INVALID_INPUT_FORMAT[] = {
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition *states[] = {
    STATUS,
    MESSAGE,
    END,
    INVALID_INPUT_FORMAT,
};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t states_n[] = {
    N(STATUS),
    N(MESSAGE),
    N(END),
    N(INVALID_INPUT_FORMAT),
};

static struct parser_definition definition = {
        .states_count = N(states),
        .states       = states,
        .states_n     = states_n,
        .start_state  = ST_STATUS,
};

struct auth_response * auth_response_parser_init(){
    struct auth_response * ans = calloc(1, sizeof(*ans));
    ans->parser = parser_init(parser_no_classes(), &definition);
    return ans;
}

struct auth_response * auth_response_parser_consume(uint8_t *s, size_t length, struct auth_response * ans) {
    for (size_t i = 0; i<length; i++) {
        const struct parser_event* ret = parser_feed(ans->parser, s[i]);
        switch (ret->type) {
            case COPY_STATUS:
                ans->status = s[i];
            break;
            case COPY_MESSAGE:
                add_char_to_message(ans, s[i], &(ans->message_length));
            break;
            case END_T:
                add_char_to_message(ans, '\0', &(ans->message_length));
                ans->finished = 1;
            break;
            case INVALID_INPUT_FORMAT_T:
                return error(ans, INVALID_INPUT_FORMAT_ERROR);
        }
    }
    return ans;
}

void auth_response_free(struct auth_response *auth_response) {
    if (auth_response != NULL) {
        if (auth_response->message != NULL) {
            free(auth_response->message);
            auth_response->message = NULL;
        }
        if(auth_response->parser != NULL){
            parser_destroy(auth_response->parser);
            auth_response->parser = NULL;
        }
        free(auth_response);
    }
}

static struct auth_response *
add_char_to_message(struct auth_response *ans, char c, size_t *message_current_length) {
    ans->message = resize_if_needed(ans->message, sizeof(*(ans->message)), *message_current_length);
    if (ans->message == NULL) {
        return error(ans, REALLOC_ERROR);
    }
    ans->message[(*message_current_length)++] = c;
    return ans;
}

static struct auth_response *error(struct auth_response *ans, parser_error_t error_type) {
    auth_response_free(ans);
    ans = calloc(1, sizeof(*ans));
    ans->error = error_type;
    return ans;
}

static void *resize_if_needed(void *ptr, size_t ptr_size, size_t current_length) {
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

    struct auth_response * ans = auth_response_parser_init();
    ans = auth_response_parser_consume(buffer, i, ans);
    free(buffer);
    if(ans->error != NO_ERROR){
        printf("error\n");
    } else {
        printf("%u\n", ans->status);
        printf("%s\n", ans->message);
    }
    auth_response_free(ans);
    return 0;
}
*/