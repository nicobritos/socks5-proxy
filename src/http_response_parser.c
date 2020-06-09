#include <stdio.h>
#include <stdlib.h>

#include "parser.h"
#include "http_response_parser.h"

#define CHUNK_SIZE 10

/* Funciones auxiliares */
void * resize_if_needed(void * ptr, size_t ptr_size, size_t current_length);
struct http_response * add_char_to_data(struct http_response * ans, char c, size_t * data_current_length);
struct http_response * add_char_to_code_description(struct http_response * ans, char c, size_t * code_description_current_length);
struct http_response * error(struct http_response * ans, error_t error_type);

// definición de maquina

enum states {
    ST_START,
    ST_H,
    ST_T,
    ST_T_2,
    ST_P,
    ST_BAR,
    ST_1,
    ST_DOT,
    ST_1_2,
    ST_SPACE,
    ST_STATUS_CODE_1,
    ST_STATUS_CODE_2,
    ST_STATUS_CODE_3,
    ST_CODE_DESC,
    ST_CODE_DESC_POSSIBLE_END,
    ST_HEADERS,
    ST_HEADER_POSSIBLE_END,
    ST_HEADER_END,
    ST_HEADERS_POSSIBLE_END,
    ST_DATA,
    ST_FINISHED,
    ST_INVALID_INPUT_FORMAT,
};

enum event_type {
    SUCCESS,
    COPY_STATUS_1,
    COPY_STATUS_2,
    COPY_STATUS_3,
    COPY_DATA,
    END_COPY_DATA,
    COPY_STATUS_DESC,
    COPY_STATUS_DESC_R,
    END_COPY_STATUS_DESC,
    INVALID_INPUT_FORMAT,
};

static void
next_state(struct parser_event *ret, const uint8_t c) {
    ret->type    = SUCCESS;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_status_1(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_STATUS_1;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_status_2(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_STATUS_2;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_status_3(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_STATUS_3;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_status_desc(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_STATUS_DESC;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_status_desc_r(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_STATUS_DESC_R;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
end_copy_status_desc(struct parser_event *ret, const uint8_t c) {
    ret->type    = END_COPY_STATUS_DESC;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_data(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_DATA;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
end_copy_data(struct parser_event *ret, const uint8_t c) {
    ret->type    = END_COPY_DATA;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
invalid_input(struct parser_event *ret, const uint8_t c) {
    ret->type    = INVALID_INPUT_FORMAT;
    ret->n       = 1;
    ret->data[0] = c;
}

static const struct parser_state_transition START [] =  {
    {.when = 'H',        .dest = ST_H,                          .act1 = next_state,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
};

static const struct parser_state_transition H [] =  {
    {.when = 'T',        .dest = ST_T,             .act1 = next_state,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
};

static const struct parser_state_transition T [] =  {
    {.when = 'T',        .dest = ST_T_2,           .act1 = next_state,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
};

static const struct parser_state_transition T_2 [] =  {
    {.when = 'P',        .dest = ST_P,             .act1 = next_state,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
};

static const struct parser_state_transition P [] =  {
    {.when = '/',        .dest = ST_BAR,           .act1 = next_state,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
};

static const struct parser_state_transition BAR [] =  {
    {.when = '1',        .dest = ST_1,             .act1 = next_state,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
};

static const struct parser_state_transition ONE [] =  {
    {.when = '.',        .dest = ST_DOT,           .act1 = next_state,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
};

static const struct parser_state_transition DOT [] =  {
    {.when = '1',        .dest = ST_1_2,           .act1 = next_state,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
};

static const struct parser_state_transition ONE_2 [] =  {
    {.when = ' ',        .dest = ST_SPACE,         .act1 = next_state,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
};

static const struct parser_state_transition SPACE [] =  {
    {.when = '1',        .dest = ST_STATUS_CODE_1,              .act1 = copy_status_1,},
    {.when = '2',        .dest = ST_STATUS_CODE_1,              .act1 = copy_status_1,},
    {.when = '3',        .dest = ST_STATUS_CODE_1,              .act1 = copy_status_1,},
    {.when = '4',        .dest = ST_STATUS_CODE_1,              .act1 = copy_status_1,},
    {.when = '5',        .dest = ST_STATUS_CODE_1,              .act1 = copy_status_1,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
};

static const struct parser_state_transition STATUS_1 [] =  {
    {.when = '0',        .dest = ST_STATUS_CODE_2,              .act1 = copy_status_2,},
    {.when = '1',        .dest = ST_STATUS_CODE_2,              .act1 = copy_status_2,},
    {.when = '2',        .dest = ST_STATUS_CODE_2,              .act1 = copy_status_2,},
    {.when = '3',        .dest = ST_STATUS_CODE_2,              .act1 = copy_status_2,},
    {.when = '4',        .dest = ST_STATUS_CODE_2,              .act1 = copy_status_2,},
    {.when = '5',        .dest = ST_STATUS_CODE_2,              .act1 = copy_status_2,},
    {.when = '6',        .dest = ST_STATUS_CODE_2,              .act1 = copy_status_2,},
    {.when = '7',        .dest = ST_STATUS_CODE_2,              .act1 = copy_status_2,},
    {.when = '8',        .dest = ST_STATUS_CODE_2,              .act1 = copy_status_2,},
    {.when = '9',        .dest = ST_STATUS_CODE_2,              .act1 = copy_status_2,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
};

static const struct parser_state_transition STATUS_2 [] =  {
    {.when = '0',        .dest = ST_STATUS_CODE_3,              .act1 = copy_status_3,},
    {.when = '1',        .dest = ST_STATUS_CODE_3,              .act1 = copy_status_3,},
    {.when = '2',        .dest = ST_STATUS_CODE_3,              .act1 = copy_status_3,},
    {.when = '3',        .dest = ST_STATUS_CODE_3,              .act1 = copy_status_3,},
    {.when = '4',        .dest = ST_STATUS_CODE_3,              .act1 = copy_status_3,},
    {.when = '5',        .dest = ST_STATUS_CODE_3,              .act1 = copy_status_3,},
    {.when = '6',        .dest = ST_STATUS_CODE_3,              .act1 = copy_status_3,},
    {.when = '7',        .dest = ST_STATUS_CODE_3,              .act1 = copy_status_3,},
    {.when = '8',        .dest = ST_STATUS_CODE_3,              .act1 = copy_status_3,},
    {.when = '9',        .dest = ST_STATUS_CODE_3,              .act1 = copy_status_3,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
};

static const struct parser_state_transition STATUS_3 [] =  {
    {.when = ' ',        .dest = ST_CODE_DESC,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
};

static const struct parser_state_transition DESC [] =  {
    {.when = '\r',       .dest = ST_CODE_DESC_POSSIBLE_END,     .act1 = next_state,},
    {.when = '\0',       .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
    {.when = ANY,        .dest = ST_CODE_DESC,                  .act1 = copy_status_desc,},
};

static const struct parser_state_transition CODE_DESC_POSSIBLE_END [] =  {
    {.when = '\n',       .dest = ST_HEADERS,                    .act1 = end_copy_status_desc,},
    {.when = '\0',       .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
    {.when = ANY,        .dest = ST_CODE_DESC,                  .act1 = copy_status_desc_r,},
};

static const struct parser_state_transition HEADER [] =  {
    {.when = '\r',       .dest = ST_HEADER_POSSIBLE_END,        .act1 = next_state,},
    {.when = '\0',       .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
    {.when = ANY,        .dest = ST_HEADERS,                    .act1 = next_state,},
};

static const struct parser_state_transition HEADER_POSSIBLE_END [] =  {
    {.when = '\n',       .dest = ST_HEADER_END,                 .act1 = next_state,},
    {.when = '\0',       .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
    {.when = ANY,        .dest = ST_HEADERS,                    .act1 = next_state,},
};

static const struct parser_state_transition HEADER_END [] =  {
    {.when = '\r',       .dest = ST_HEADERS_POSSIBLE_END,       .act1 = next_state,},
    {.when = '\0',       .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
    {.when = ANY,        .dest = ST_HEADERS,                    .act1 = next_state,},
};

static const struct parser_state_transition HEADERS_POSSIBLE_END [] =  {
    {.when = '\n',       .dest = ST_DATA,                       .act1 = next_state,},
    {.when = '\0',       .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
    {.when = ANY,        .dest = ST_HEADERS,                    .act1 = next_state,},
};

static const struct parser_state_transition DATA [] =  {
    {.when = '\0',       .dest = ST_FINISHED,                   .act1 = end_copy_data,},
    {.when = ANY,        .dest = ST_DATA,                       .act1 = copy_data,},
};

static const struct parser_state_transition *states [] = {
    START,
    H,
    T,
    T_2,
    P,
    BAR,
    ONE,
    DOT,
    ONE_2,
    SPACE,
    STATUS_1,
    STATUS_2,
    STATUS_3,
    DESC,
    CODE_DESC_POSSIBLE_END,
    HEADER,
    HEADER_POSSIBLE_END,
    HEADER_END,
    HEADERS_POSSIBLE_END,
    DATA,
};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t states_n [] = {
    N(START),
    N(H),
    N(T),
    N(T_2),
    N(P),
    N(BAR),
    N(ONE),
    N(DOT),
    N(ONE_2),
    N(SPACE),
    N(STATUS_1),
    N(STATUS_2),
    N(STATUS_3),
    N(DESC),
    N(CODE_DESC_POSSIBLE_END),
    N(HEADER),
    N(HEADER_POSSIBLE_END),
    N(HEADER_END),
    N(HEADERS_POSSIBLE_END),
    N(DATA),
};

static struct parser_definition definition = {
    .states_count = N(states),
    .states       = states,
    .states_n     = states_n,
    .start_state  = ST_START,
};

struct http_response * http_response_parser(char * s){
    struct parser *parser = parser_init(parser_no_classes(), &definition);
    struct http_response * ans = calloc(1, sizeof(*ans));
    size_t code_description_current_length = 0;
    size_t data_current_length = 0;
    for(int i = 0; s[i]; i++){
        struct parser_event* ret = parser_feed(parser, s[i]);
        switch (ret->type){
            case COPY_STATUS_1:
                ans->status_code = ((ret->data[0]) - '0') * 100;
            break;
            case COPY_STATUS_2:
                ans->status_code += ((ret->data[0]) - '0') * 10;
            break;
            case COPY_STATUS_3:
                ans->status_code += ((ret->data[0]) - '0');
            break;
            case COPY_STATUS_DESC:
                add_char_to_code_description(ans, ret->data[0], &code_description_current_length);
            break;
            case COPY_STATUS_DESC_R:
                add_char_to_code_description(ans, '\r', &code_description_current_length);
                add_char_to_code_description(ans, ret->data[0], &code_description_current_length);
            break;
            case END_COPY_STATUS_DESC:
                add_char_to_code_description(ans, '\0', &code_description_current_length);
                ans->code_description = realloc(ans->code_description, sizeof(*(ans->code_description)) * code_description_current_length); // acorto el string si le sobra espacio
                if(ans->code_description == NULL){
                    return error(ans, REALLOC_ERROR);
                }
            break;
            case COPY_DATA:
                add_char_to_data(ans, ret->data[0], &data_current_length);
            break;
            case END_COPY_DATA:
                add_char_to_data(ans, '\0', &data_current_length);
                ans->code_description = realloc(ans->code_description, sizeof(*(ans->data)) * data_current_length); // acorto el string si le sobra espacio
                if(ans->code_description == NULL){
                    return error(ans, REALLOC_ERROR);
                }
            break;
            case INVALID_INPUT_FORMAT:
                return error(ans, INVALID_INPUT_FORMAT_ERROR);
            break;
        }
    }
    return ans;
}

void free_http_response(struct http_response * ans){
    if(ans != NULL){
        free(ans->data);
        free(ans->code_description);
        free(ans);
    }
}

struct http_response * add_char_to_code_description(struct http_response * ans, char c, size_t * code_description_current_length){
    ans->code_description = resize_if_needed(ans->code_description, sizeof(*(ans->code_description)), *code_description_current_length);
    if(ans->code_description == NULL){
        return error(ans, REALLOC_ERROR);
    }
    ans->code_description[(*code_description_current_length)++] = c;
    return ans;
}

struct http_response * add_char_to_data(struct http_response * ans, char c, size_t * data_current_length){
    ans->data = resize_if_needed(ans->data, sizeof(*(ans->data)), *data_current_length);
    if(ans->data == NULL){
        return error(ans, REALLOC_ERROR);
    }
    ans->data[(*data_current_length)++] = c;
    return ans;
}

struct http_response * error(struct http_response * ans, error_t error_type){
    free_http_response(ans);
    ans = malloc(sizeof(*ans));
    ans->data = NULL;
    ans->code_description = NULL;
    ans->status_code = error_type;
    return ans;
}

void * resize_if_needed(void * ptr, size_t ptr_size, size_t current_length){
    if(current_length % CHUNK_SIZE == 0){
        return realloc(ptr, ptr_size * (current_length + CHUNK_SIZE));
    }
    return ptr;
}

/** 
 * To test with afl-fuzz uncomment the main function below and run:
 *     1. Create a directory for example inputs (i.e. parser_test_case)
 *     2. Insert at least 1 (one) example file in the created directory
 *     3. Run in the terminal "afl-clang http_response_parser.c parser.c -o http_response -pedantic -std=c99" (or afl-gcc)
 *     4. Run in the terminal "afl-fuzz -i parser_test_case -o afl-output -- ./http_response @@"
 */

/*
int main(int argc, char ** argv){
    FILE * fp;
    char c;
    char buffer[1000];
    if(argc != 2){
        return 1;
    }
    fp = fopen(argv[1], "r");
    int i = 0;
    while((c=fgetc(fp)) != EOF){
        buffer[i] = c;
        i++;
    }
    buffer[i] = '\0';
    fclose(fp);

    struct http_response * ans = http_response_parser(buffer);
    printf("%d\n", ans->status_code);
    printf("%s\n", ans->code_description);
    printf("%s\n", ans->data);
    free_http_response(ans);
    return 0;
}
*/