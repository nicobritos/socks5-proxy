#include <stdio.h>
#include <stdlib.h>

#include "../../../utils/parser.h"
#include "command_request_parser.h"

#define CHUNK_SIZE 10

/* Funciones auxiliares */
static void *resize_if_needed(void *ptr, size_t ptr_size, size_t current_length);

static struct command *error(struct command *ans, parser_error_t error_type);

static parser_error_t add_to_string(char ** s, uint8_t c, size_t * current_length);

static parser_error_t add_to_byte_array(uint8_t ** s, uint8_t c, size_t * current_length);

// definición de maquina

enum states {
    ST_CODE,
    ST_USER_6,
    ST_PASS_6,
    ST_MODE_6,
    ST_VCODE_7,
    ST_IO_TIMEOUT_VVAL_7,
    ST_LMODE_7,
    ST_END,
    ST_INVALID_INPUT_FORMAT,
};

enum event_type {
    SUCCESS,
    COPY_CODE,
    COPY_6_USER,
    COPY_6_PASS,
    COPY_6_MODE,
    COPY_7_VCODE,
    COPY_7_IO_TIMEOUT,
    COPY_7_LMODE,
    INVALID_INPUT_FORMAT_T,
};

static void
copy_code(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_CODE;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_6_user(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_6_USER;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_6_pass(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_6_PASS;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_6_mode(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_6_MODE;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_7_vcode(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_7_VCODE;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_7_io_timeout(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_7_IO_TIMEOUT;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_7_lmode(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_7_LMODE;
    ret->n = 1;
    ret->data[0] = c;
}
    

static void
invalid_input(struct parser_event *ret, const uint8_t c) {
    ret->type = INVALID_INPUT_FORMAT_T;
    ret->n = 1;
    ret->data[0] = c;
}

static const struct parser_state_transition CODE[] = {
    {.when = 1, .dest = ST_END, .act1 = copy_code,},
    {.when = 2, .dest = ST_END, .act1 = copy_code,},
    {.when = 3, .dest = ST_END, .act1 = copy_code,},
    {.when = 4, .dest = ST_END, .act1 = copy_code,},
    {.when = 5, .dest = ST_END, .act1 = copy_code,},
    {.when = 6, .dest = ST_USER_6, .act1 = copy_code,},
    {.when = 7, .dest = ST_VCODE_7, .act1 = copy_code,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition USER_6[] = {
    {.when = '\0', .dest = ST_PASS_6, .act1 = copy_6_user,},
    {.when = ANY, .dest = ST_USER_6, .act1 = copy_6_user,},
};

static const struct parser_state_transition PASS_6[] = {
    {.when = '\0', .dest = ST_MODE_6, .act1 = copy_6_pass,},
    {.when = ANY, .dest = ST_PASS_6, .act1 = copy_6_pass,},
};

static const struct parser_state_transition MODE_6[] = {
    {.when = 0, .dest = ST_END, .act1 = copy_6_mode,},
    {.when = 1, .dest = ST_END, .act1 = copy_6_mode,},
    {.when = 2, .dest = ST_END, .act1 = copy_6_mode,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition VCODE_7[] = {
    {.when = 1, .dest = ST_IO_TIMEOUT_VVAL_7, .act1 = copy_7_vcode,},
    {.when = 2, .dest = ST_LMODE_7, .act1 = copy_7_vcode,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition IO_TIMEOUT_VVAL_7[] = {
    {.when = ANY, .dest = ST_IO_TIMEOUT_VVAL_7, .act1 = copy_7_io_timeout,},
};

static const struct parser_state_transition LMODE_7[] = {
    {.when = 1, .dest = ST_END, .act1 = copy_7_lmode,},
    {.when = 2, .dest = ST_END, .act1 = copy_7_lmode,},
    {.when = 3, .dest = ST_END, .act1 = copy_7_lmode,},
    {.when = 4, .dest = ST_END, .act1 = copy_7_lmode,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition END[] = {
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition INVALID_INPUT_FORMAT[] = {
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition *states[] = {
    CODE,
    USER_6,
    PASS_6,
    MODE_6,
    VCODE_7,
    IO_TIMEOUT_VVAL_7,
    LMODE_7,
    END,
    INVALID_INPUT_FORMAT,
};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t states_n[] = {
    N(CODE),
    N(USER_6),
    N(PASS_6),
    N(MODE_6),
    N(VCODE_7),
    N(IO_TIMEOUT_VVAL_7),
    N(LMODE_7),
    N(END),
    N(INVALID_INPUT_FORMAT),
};

static struct parser_definition definition = {
        .states_count = N(states),
        .states       = states,
        .states_n     = states_n,
        .start_state  = ST_CODE,
};

struct command * command_request_parser_init(){
    struct command * ans = calloc(1, sizeof(*ans));
    ans->parser = parser_init(parser_no_classes(), &definition);
    return ans;
}

struct command * command_request_parser_consume(uint8_t *s, size_t length, struct command * ans) {
    parser_error_t ans_error = NO_ERROR;
    for (size_t i = 0; i<length; i++) {
        const struct parser_event* ret = parser_feed(ans->parser, s[i]);
        switch (ret->type) {
            case COPY_CODE:
                ans->code = s[i];
            break;
            case COPY_6_USER:
                ans_error = add_to_string(&(ans->user), s[i], &(ans->user_current_length));
                if(ans_error != NO_ERROR){
                    return error(ans, ans_error);
                }
            break;
            case COPY_6_PASS:
                ans_error = add_to_string(&(ans->password), s[i], &(ans->pass_current_length));
                if(ans_error != NO_ERROR){
                    return error(ans, ans_error);
                }
            break;
            case COPY_6_MODE:
                ans->mode = s[i];
            break;
            case COPY_7_VCODE:
                ans->var = s[i];
            break;
            case COPY_7_IO_TIMEOUT:
                ans_error = add_to_byte_array(&(ans->var_value), s[i], &(ans->var_value_length));
                if(ans_error != NO_ERROR){
                    return error(ans, ans_error);
                }
            break;
            case COPY_7_LMODE:
                ans_error = add_to_byte_array(&(ans->var_value), s[i], &(ans->var_value_length));
                if(ans_error != NO_ERROR){
                    return error(ans, ans_error);
                }
            break;
            case INVALID_INPUT_FORMAT_T:
                return error(ans, INVALID_INPUT_FORMAT_ERROR);
        }
    }
    return ans;
}

void free_command(struct command *command) {
    if (command != NULL) {
        if(command->user != NULL){
            free(command->user);
        }
        if(command->password != NULL){
            free(command->password);
        }
        if(command->var_value != NULL){
            free(command->var_value);
        }
        if(command->parser != NULL){
            parser_destroy(command->parser);
        }
        free(command);
    }
}

static struct command *error(struct command *ans, parser_error_t error_type) {
    free_command(ans);
    ans = calloc(1, sizeof(*ans));
    ans->error = error_type;
    return ans;
}

static parser_error_t add_to_string(char ** s, uint8_t c, size_t * current_length){
    *s = resize_if_needed(*s, sizeof(**s), *current_length);
    if(*s == NULL){
        return REALLOC_ERROR;
    }
    (*s)[*current_length] = c;
    (*current_length)++;
    return NO_ERROR;
}

static parser_error_t add_to_byte_array(uint8_t ** s, uint8_t c, size_t * current_length){
    *s = resize_if_needed(*s, sizeof(**s), *current_length);
    if(*s == NULL){
        return REALLOC_ERROR;
    }
    (*s)[*current_length] = c;
    (*current_length)++;
    return NO_ERROR;
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

    struct command * ans = command_request_parser(buffer, i);
    free(buffer);
    if(ans->error != NO_ERROR){
        printf("error\n");
    } else {
        printf("Code = %u\n", ans->code);
        if(ans->code == SET_USER){
            printf("User = %s\n", ans->user);
            printf("Password = %s\n", ans->password);
            printf("Mode = %u\n", ans->mode);
        } else if(ans->code == SET_VAR){
            printf("Var Code = %u\n", ans->var);
            for(int i = 0; i<ans->var_value_length; i++){
                printf("Var Value - Byte %d = %02x\n", i, ans->var_value[i]);
            }
        }
    }
    free_command(ans);
    return 0;
}
*/