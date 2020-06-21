#include <stdio.h>
#include <stdlib.h>

#include "../../utils/parser.h"
#include "get_users_parser.h"

#define CHUNK_SIZE 10

/* Funciones auxiliares */
void *resize_if_needed(void *ptr, size_t ptr_size, size_t current_length);

struct users *error(struct users *ans, get_users_parser_error_t error_type);

// definición de maquina

enum states {
    ST_START,
    ST_USER,
    ST_STATUS,
    ST_END_USER,
    ST_END,
    ST_INVALID_INPUT_FORMAT,
};

enum event_type {
    SUCCESS,
    COPY_USER,
    COPY_STATUS,
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
copy_user(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_USER;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_status(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_STATUS;
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

static const struct parser_state_transition START[] = {
    {.when = '\0', .dest = ST_END, .act1 = end,},
    {.when = ANY, .dest = ST_USER, .act1 = copy_user,},
};

static const struct parser_state_transition USER[] = {
    {.when = '\0', .dest = ST_STATUS, .act1 = copy_user,},
    {.when = ANY, .dest = ST_USER, .act1 = copy_user,},
};

static const struct parser_state_transition STATUS[] = {
    {.when = '\0', .dest = ST_END_USER, .act1 = copy_status,},
    {.when = '\1', .dest = ST_END_USER, .act1 = copy_status,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition END_USER[] = {
    {.when = '\0', .dest = ST_END, .act1 = end,},
    {.when = ANY, .dest = ST_USER, .act1 = copy_user,},
};

static const struct parser_state_transition END[] = {
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition INVALID_INPUT_FORMAT[] = {
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition *states[] = {
    START,
    USER,
    STATUS,
    END_USER,
    END,
    INVALID_INPUT_FORMAT,
};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t states_n[] = {
    N(START),
    N(USER),
    N(STATUS),
    N(END_USER),
    N(END),
    N(INVALID_INPUT_FORMAT),
};

static struct parser_definition definition = {
        .states_count = N(states),
        .states       = states,
        .states_n     = states_n,
        .start_state  = ST_START,
};

struct users * get_users_parser(uint8_t *s, size_t length) {
    struct users * ans = calloc(1, sizeof(*ans));
    struct parser *parser = parser_init(parser_no_classes(), &definition);
    size_t current_user_length = 0;
    int finished = 0;
    for (size_t i = 0; i<length; i++) {
        const struct parser_event* ret = parser_feed(parser, s[i]);
        switch (ret->type) {
            case COPY_USER:
                if(current_user_length == 0){
                    ans->users = resize_if_needed(ans->users, sizeof(*(ans->users)), ans->users_qty);
                    if(ans->users == NULL){
                        parser_destroy(parser);
                        return error(ans, REALLOC_ERROR);
                    }
                    ans->users[ans->users_qty].user = NULL;
                }
                ans->users[ans->users_qty].user  = resize_if_needed(ans->users[ans->users_qty].user , sizeof(*(ans->users[ans->users_qty].user)), current_user_length);
                if(ans->users[ans->users_qty].user == NULL){
                    parser_destroy(parser);
                    return error(ans, REALLOC_ERROR);
                }
                ans->users[ans->users_qty].user[current_user_length++] = s[i];
            break;
            case COPY_STATUS:
                current_user_length = 0;
                ans->users[(ans->users_qty)++].status = s[i];
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
        if(current_user_length != 0){
            free(ans->users[ans->users_qty].user); // Libero el string que estaba armando
        }
        parser_destroy(parser);
        return error(ans, INVALID_INPUT_FORMAT_ERROR);
    }
    parser_destroy(parser);
    return ans;
}

void free_users(struct users *users) {
    if (users != NULL) {
        if(users->users != NULL){
            for(int i = 0; i<users->users_qty; i++){
                free(users->users[i].user);
            }
            free(users->users);
            users->users_qty = 0;
        }
        free(users);
    }
}

struct users *error(struct users *ans, get_users_parser_error_t error_type) {
    free_users(ans);
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
 *     3. Run in the terminal "afl-clang get_users_parser.c parser.c -o get_users_parser -pedantic -std=c99" (or afl-gcc)
 *     4. Run in the terminal "afl-fuzz -i parser_test_case -o afl-output -- ./get_users_parser @@"
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

    struct users * ans = get_users_parser(buffer, i);
    free(buffer);
    if(ans->error != NO_ERROR){
        printf("error\n");
    } else {
        printf("Cantidad de usuarios: %zu\n", ans->users_qty);
        for(int i = 0; i<ans->users_qty; i++){
            printf("User: %s\tStatus: %d\n", ans->users[i].user, ans->users[i].status);
        }
    }
    free_users(ans);
    return 0;
}
*/