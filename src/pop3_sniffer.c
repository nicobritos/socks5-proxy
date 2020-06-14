#include <stdio.h>
#include <stdlib.h>

#include "parser.h"
#include "pop3_sniffer.h"

#define CHUNK_SIZE 10

/* Funciones auxiliares */
struct pop3_credentials * add_char_to_user(struct pop3_credentials * ans, char c);
struct pop3_credentials * add_char_to_password(struct pop3_credentials * ans, char c);
void * resize_if_needed(void * ptr, size_t ptr_size, size_t current_length);
struct pop3_credentials * error(struct pop3_credentials * ans, error_t error_type);

// definición de maquina

enum states {
    ST_START,
    ST_UNIMPORTANT_LINE,
    ST_USER_U,
    ST_USER_S,
    ST_USER_E,
    ST_USER_R,
    ST_USER_SPACE,
    ST_USERNAME,
    ST_USERNAME_END,
    ST_USER_RESPONSE_OK_PLUS,
    ST_USER_RESPONSE_ERR,
    ST_USER_RESPONSE_OK_O,
    ST_USER_RESPONSE_OK_K,
    ST_USER_RESPONSE_OK_SPACE,
    ST_USER_RESPONSE_OK_END,
    ST_PASS_P,
    ST_PASS_A,
    ST_PASS_S,
    ST_PASS_S_2,
    ST_PASS_SPACE,
    ST_PASSWORD,
    ST_PASSWORD_END,
    ST_PASS_RESPONSE_OK_PLUS,
    ST_PASS_RESPONSE_ERR,
    ST_PASS_RESPONSE_OK_O,
    ST_FINISHED,
};

enum event_type {
    SUCCESS,
    COPY_USER,
    END_COPY_USER,
    ERASE_USER,
    COPY_PASS,
    END_COPY_PASS,
    ERASE_PASS,
    FINISHED_T,
};

static void
next_state(struct parser_event *ret, const uint8_t c) {
    ret->type    = SUCCESS;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_user(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_USER;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
end_copy_user(struct parser_event *ret, const uint8_t c) {
    ret->type    = END_COPY_USER;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
erase_user(struct parser_event *ret, const uint8_t c) {
    ret->type    = ERASE_USER;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_pass(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_PASS;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
end_copy_pass(struct parser_event *ret, const uint8_t c) {
    ret->type    = END_COPY_PASS;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
erase_pass(struct parser_event *ret, const uint8_t c) {
    ret->type    = ERASE_PASS;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
finished(struct parser_event *ret, const uint8_t c) {
    ret->type    = FINISHED_T;
    ret->n       = 1;
    ret->data[0] = c;
}



static const struct parser_state_transition START [] =  {
    {.when = 'U',        .dest = ST_USER_U,                 .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition UNIMPORTANT_LINE [] =  {
    {.when = '\n',       .dest = ST_START,                 .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition USER_U [] =  {
    {.when = 'S',        .dest = ST_USER_S,                 .act1 = next_state,},
    {.when = '\0',       .dest = ST_USER_U,                 .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition USER_S [] =  {
    {.when = 'E',        .dest = ST_USER_E,                 .act1 = next_state,},
    {.when = '\0',       .dest = ST_USER_S,                 .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition USER_E [] =  {
    {.when = 'R',        .dest = ST_USER_R,                 .act1 = next_state,},
    {.when = '\0',       .dest = ST_USER_E,                 .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition USER_R [] =  {
    {.when = ' ',        .dest = ST_USER_SPACE,             .act1 = next_state,},
    {.when = '\0',       .dest = ST_USER_R,                 .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition USER_SPACE [] =  {
    {.when = '\0',       .dest = ST_USER_SPACE,             .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_USERNAME,               .act1 = copy_user,},
};

static const struct parser_state_transition USERNAME [] =  {
    {.when = '\0',       .dest = ST_USERNAME,               .act1 = next_state,},
    {.when = '\n',       .dest = ST_USERNAME_END,           .act1 = end_copy_user,},
    {.when = ANY,        .dest = ST_USERNAME,               .act1 = copy_user,},
};

static const struct parser_state_transition USERNAME_END [] =  {
    {.when = '+',        .dest = ST_USER_RESPONSE_OK_PLUS,  .act1 = next_state,},
    {.when = '-',        .dest = ST_USER_RESPONSE_ERR,      .act1 = erase_user,},
    {.when = '\0',       .dest = ST_USERNAME_END,           .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition USER_RESPONSE_ERR [] =  {
    {.when = '\0',       .dest = ST_USER_RESPONSE_ERR,      .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition USER_RESPONSE_OK_PLUS [] =  {
    {.when = 'O',        .dest = ST_USER_RESPONSE_OK_O,     .act1 = next_state,},
    {.when = '\0',       .dest = ST_USER_RESPONSE_OK_PLUS,  .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition USER_RESPONSE_OK_O [] =  {
    {.when = 'K',        .dest = ST_USER_RESPONSE_OK_K,     .act1 = next_state,},
    {.when = '\0',       .dest = ST_USER_RESPONSE_OK_O,     .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition USER_RESPONSE_OK_K [] =  {
    {.when = ' ',        .dest = ST_USER_RESPONSE_OK_SPACE, .act1 = next_state,},
    {.when = '\0',       .dest = ST_USER_RESPONSE_OK_K,     .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition USER_RESPONSE_OK_SPACE [] =  {
    {.when = '\0',       .dest = ST_USER_RESPONSE_OK_SPACE, .act1 = next_state,},
    {.when = ANY,        .dest = ST_USER_RESPONSE_OK_END,   .act1 = next_state,},
};

static const struct parser_state_transition USER_RESPONSE_OK_END [] =  {
    {.when = 'P',        .dest = ST_PASS_P,                 .act1 = next_state,},
    {.when = '\0',       .dest = ST_USER_RESPONSE_OK_END,   .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition PASS_P [] =  {
    {.when = 'A',        .dest = ST_PASS_A,                 .act1 = next_state,},
    {.when = '\0',       .dest = ST_PASS_P,                 .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition PASS_A [] =  {
    {.when = 'S',        .dest = ST_PASS_S,                 .act1 = next_state,},
    {.when = '\0',       .dest = ST_PASS_A,                 .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition PASS_S [] =  {
    {.when = 'S',        .dest = ST_PASS_S_2,               .act1 = next_state,},
    {.when = '\0',       .dest = ST_PASS_S,                 .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition PASS_S_2 [] =  {
    {.when = ' ',        .dest = ST_PASS_SPACE,               .act1 = next_state,},
    {.when = '\0',       .dest = ST_PASS_S_2,                 .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition PASS_SPACE [] =  {
    {.when = '\0',       .dest = ST_PASS_SPACE,             .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_PASSWORD,               .act1 = copy_pass,},
};

static const struct parser_state_transition PASSWORD [] =  {
    {.when = '\0',       .dest = ST_PASSWORD,               .act1 = next_state,},
    {.when = '\n',       .dest = ST_PASSWORD_END,           .act1 = end_copy_pass,},
    {.when = ANY,        .dest = ST_PASSWORD,               .act1 = copy_pass,},
};

static const struct parser_state_transition PASSWORD_END [] =  {
    {.when = '+',        .dest = ST_PASS_RESPONSE_OK_PLUS,  .act1 = next_state,},
    {.when = '-',        .dest = ST_PASS_RESPONSE_ERR,      .act1 = erase_pass,},
    {.when = '\0',       .dest = ST_PASSWORD_END,           .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition PASS_RESPONSE_ERR [] =  {
    {.when = '\0',       .dest = ST_PASS_RESPONSE_ERR,      .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition PASS_RESPONSE_OK_PLUS [] =  {
    {.when = 'O',        .dest = ST_PASS_RESPONSE_OK_O,     .act1 = next_state,},
    {.when = '\0',       .dest = ST_PASS_RESPONSE_OK_PLUS,  .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition PASS_RESPONSE_OK_O [] =  {
    {.when = 'K',        .dest = ST_FINISHED,               .act1 = next_state,},
    {.when = '\0',       .dest = ST_PASS_RESPONSE_OK_O,     .act1 = next_state,},
    {.when = '\n',       .dest = ST_START,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_UNIMPORTANT_LINE,       .act1 = next_state,},
};

static const struct parser_state_transition FINISHED [] =  {
    {.when = ANY,        .dest = ST_FINISHED,               .act1 = finished,},
};

static const struct parser_state_transition *states [] = {
    START,
    UNIMPORTANT_LINE,
    USER_U,
    USER_S,
    USER_E,
    USER_R,
    USER_SPACE,
    USERNAME_END,
    USER_RESPONSE_ERR,
    USER_RESPONSE_OK_PLUS,
    USER_RESPONSE_OK_O,
    USER_RESPONSE_OK_K,
    USER_RESPONSE_OK_SPACE,
    USER_RESPONSE_OK_END,
    PASS_P,
    PASS_A,
    PASS_S,
    PASS_S_2,
    PASS_SPACE,
    PASSWORD,
    PASSWORD_END,
    PASS_RESPONSE_ERR,
    PASS_RESPONSE_OK_PLUS,
    PASS_RESPONSE_OK_O,
    FINISHED,
};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t states_n [] = {
    N(START),
    N(UNIMPORTANT_LINE),
    N(USER_U),
    N(USER_S),
    N(USER_E),
    N(USER_R),
    N(USER_SPACE),
    N(USERNAME_END),
    N(USER_RESPONSE_ERR),
    N(USER_RESPONSE_OK_PLUS),
    N(USER_RESPONSE_OK_O),
    N(USER_RESPONSE_OK_K),
    N(USER_RESPONSE_OK_SPACE),
    N(USER_RESPONSE_OK_END),
    N(PASS_P),
    N(PASS_A),
    N(PASS_S),
    N(PASS_S_2),
    N(PASS_SPACE),
    N(PASSWORD),
    N(PASSWORD_END),
    N(PASS_RESPONSE_ERR),
    N(PASS_RESPONSE_OK_PLUS),
    N(PASS_RESPONSE_OK_O),
    N(FINISHED),
};

static struct parser_definition definition = {
    .states_count = N(states),
    .states       = states,
    .states_n     = states_n,
    .start_state  = ST_START,
};

struct parser * pop3_sniffer_init(){
    return parser_init(parser_no_classes(), &definition);
}

void pop3_sniffer_destroy(struct parser * parser){
    parser_destroy(parser);
}

struct pop3_credentials * pop3_credentials_init(){
    struct pop3_credentials * ans = calloc(1, sizeof(*ans));
    return ans;
}

struct pop3_credentials * pop3_sniffer_consume(struct parser * parser, struct pop3_credentials * pop3_credentials, char * s){
   for(int i = 0; s[i]; i++){
        struct parser_event * ret = parser_feed(parser, s[i]);
        switch (ret->type)
        {
            case COPY_USER:
                add_char_to_user(pop3_credentials, ret->data[0]);
                break;
            case END_COPY_USER:
                add_char_to_user(pop3_credentials, '\0');
                pop3_credentials->user = realloc(pop3_credentials->user, sizeof(*(pop3_credentials->user)) * pop3_credentials->user_length);
                if(pop3_credentials->user == NULL){
                    return error(pop3_credentials, REALLOC_ERROR);
                }
                (pop3_credentials->user_length)--;
                break;
            case ERASE_USER:
                if(pop3_credentials->user != NULL){
                    free(pop3_credentials->user);
                    pop3_credentials->user = NULL;
                }
                pop3_credentials->user_length = 0;
                break;
            case COPY_PASS:
                add_char_to_password(pop3_credentials, ret->data[0]);
                break;
            case END_COPY_PASS:
                add_char_to_password(pop3_credentials, '\0');
                pop3_credentials->password = realloc(pop3_credentials->password, sizeof(*(pop3_credentials->password)) * pop3_credentials->password_length);
                if(pop3_credentials->password == NULL){
                    return error(pop3_credentials, REALLOC_ERROR);
                }
                (pop3_credentials->password_length)--;
                break;
            case ERASE_PASS:
                if(pop3_credentials->password != NULL){
                    free(pop3_credentials->password);
                    pop3_credentials->password = NULL;
                }
                pop3_credentials->password_length = 0;
                break;
        }
    }
    return pop3_credentials;
}

void free_pop3_credentials(struct pop3_credentials * pop3_credentials){
    if(pop3_credentials != NULL){
        if(pop3_credentials->user != NULL){
            free(pop3_credentials->user);
        }
        if(pop3_credentials->password != NULL){
            free(pop3_credentials->password);
        }
        free(pop3_credentials);
    }
}

struct pop3_credentials * add_char_to_user(struct pop3_credentials * ans, char c){
    ans->user = resize_if_needed(ans->user, sizeof(*(ans->user)), ans->user_length);
    if(ans->user == NULL){
        return error(ans, REALLOC_ERROR);
    }
    ans->user[(ans->user_length)++] = c;
    return ans;
}

struct pop3_credentials * add_char_to_password(struct pop3_credentials * ans, char c){
    ans->password = resize_if_needed(ans->password, sizeof(*(ans->password)), ans->password_length);
    if(ans->password == NULL){
        return error(ans, REALLOC_ERROR);
    }
    ans->password[(ans->password_length)++] = c;
    return ans;
}

struct pop3_credentials * error(struct pop3_credentials * ans, error_t error_type){
    free_pop3_credentials(ans);
    ans = calloc(1,sizeof(*ans));
    ans->error = error_type;
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
 *     3. Run in the terminal "afl-clang pop3_sniffer.c parser.c -o pop3_sniffer -pedantic -std=c99" (or afl-gcc)
 *     4. Run in the terminal "afl-fuzz -i parser_test_case -o afl-output -- ./pop3_sniffer @@"
 */

/*
int main(int argc, char ** argv){
    FILE * fp;
    char c;
    int size = 1000;
    char *buffer = calloc(1,size * sizeof(*buffer));
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
    buffer = realloc(buffer, (i+1) * sizeof(*buffer));
    buffer[i] = '\0';
    fclose(fp);

    struct pop3_credentials * ans = pop3_sniffer_consume(pop3_sniffer_init(), pop3_credentials_init(), buffer);
    printf("%d\n", ans->finished);
    if(ans->finished){
        printf("%s\n", ans->user);
        printf("%s\n", ans->password);
    }
    printf("%d\n", ans->error);
    free_pop3_credentials(ans);
    free(buffer);
    return 0;
}
*/