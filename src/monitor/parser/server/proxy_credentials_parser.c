#include <stdio.h>
#include <stdlib.h>

#include "../../../utils/parser.h"
#include "proxy_credentials_parser.h"

#define CHUNK_SIZE 10

/* Funciones auxiliares */
void *resize_if_needed(void *ptr, size_t ptr_size, size_t current_length);

struct proxy_credentials *add_char_to_username(struct proxy_credentials *ans, char c, size_t *username_current_length);

struct proxy_credentials *add_char_to_password(struct proxy_credentials *ans, char c, size_t *password_current_length);

struct proxy_credentials *error(struct proxy_credentials *ans, parser_error_t error_type);

// definición de maquina

enum states {
    ST_VERSION,
    ST_USERNAME,
    ST_PASSWORD,
    ST_END,
    ST_INVALID_INPUT_FORMAT,
};

enum event_type {
    SUCCESS,
    COPY_VERSION,
    COPY_USERNAME,
    COPY_PASSWORD,
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
copy_version(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_VERSION;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_username(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_USERNAME;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_password(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_PASSWORD;
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

static const struct parser_state_transition VERSION[] = {
    {.when = ANY, .dest = ST_USERNAME, .act1 = copy_version,},
};

static const struct parser_state_transition USERNAME[] = {
    {.when = '\0', .dest = ST_PASSWORD, .act1 = copy_username,},
    {.when = ANY, .dest = ST_USERNAME, .act1 = copy_username,},
};

static const struct parser_state_transition PASSWORD[] = {
    {.when = '\0', .dest = ST_END, .act1 = end,},
    {.when = ANY, .dest = ST_PASSWORD, .act1 = copy_password,},
};

static const struct parser_state_transition END[] = {
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition INVALID_INPUT_FORMAT[] = {
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition *states[] = {
    VERSION,
    USERNAME,
    PASSWORD,
    END,
    INVALID_INPUT_FORMAT,
};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t states_n[] = {
    N(VERSION),
    N(USERNAME),
    N(PASSWORD),
    N(END),
    N(INVALID_INPUT_FORMAT),
};

static struct parser_definition definition = {
        .states_count = N(states),
        .states       = states,
        .states_n     = states_n,
        .start_state  = ST_VERSION,
};

struct proxy_credentials * proxy_credentials_parser_init(){
    struct proxy_credentials * ans = calloc(1, sizeof(*ans));
    ans->parser = parser_init(parser_no_classes(), &definition);
}

struct proxy_credentials * proxy_credentials_parser_consume(uint8_t *s, size_t length, struct proxy_credentials * ans) {
    for (size_t i = 0; i<length; i++) {
        const struct parser_event* ret = parser_feed(ans->parser, s[i]);
        switch (ret->type) {
            case COPY_VERSION:
                ans->version = s[i];
            break;
            case COPY_USERNAME:
                ans = add_char_to_username(ans, s[i], &(ans->username_length));
            break;
            case COPY_PASSWORD:
                ans = add_char_to_password(ans, s[i], &(ans->password_length));
            break;
            case END_T:
                ans = add_char_to_password(ans, '\0', &(ans->password_length));
                ans->finished = 1;
            break;
            case INVALID_INPUT_FORMAT_T:
                return error(ans, INVALID_INPUT_FORMAT_ERROR);
        }
    }
    return ans;
}

void proxy_credentials_free(struct proxy_credentials *proxy_credentials) {
    if (proxy_credentials != NULL) {
        if (proxy_credentials->username != NULL) {
            free(proxy_credentials->username);
        }
        if (proxy_credentials->password != NULL) {
            free(proxy_credentials->password);
        }
        if(proxy_credentials->parser != NULL){
            parser_destroy(proxy_credentials->parser);
        }
        free(proxy_credentials);
    }
}

struct proxy_credentials *
add_char_to_username(struct proxy_credentials *ans, char c, size_t *username_current_length) {
    ans->username = resize_if_needed(ans->username, sizeof(*(ans->username)), *username_current_length);
    if (ans->username == NULL) {
        return error(ans, REALLOC_ERROR);
    }
    ans->username[(*username_current_length)++] = c;
    return ans;
}

struct proxy_credentials *
add_char_to_password(struct proxy_credentials *ans, char c, size_t *password_current_length) {
    ans->password = resize_if_needed(ans->password, sizeof(*(ans->password)), *password_current_length);
    if (ans->password == NULL) {
        return error(ans, REALLOC_ERROR);
    }
    ans->password[(*password_current_length)++] = c;
    return ans;
}

struct proxy_credentials *error(struct proxy_credentials *ans, parser_error_t error_type) {
    proxy_credentials_free(ans);
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
 *     3. Run in the terminal "afl-clang proxy_credentials_parser.c parser.c -o proxy_credentials_parser -pedantic -std=c99" (or afl-gcc)
 *     4. Run in the terminal "afl-fuzz -i parser_test_case -o afl-output -- ./proxy_credentials_parser @@"
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

    struct proxy_credentials * ans = proxy_credentials_parser(buffer, i);
    free(buffer);
    if(ans->error != 0){
        printf("error\n");
    } else {
        printf("%u\n", ans->version);
        printf("%s\n", ans->username);
        printf("%s\n", ans->password);
    }
    proxy_credentials_free(ans);
    return 0;
}
*/