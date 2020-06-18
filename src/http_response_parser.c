#include <stdio.h>
#include <stdlib.h>

#include "parser.h"
#include "http_response_parser.h"

#define CHUNK_SIZE 10

/* Funciones auxiliares */
void * resize_if_needed(void * ptr, size_t ptr_size, size_t current_length);
struct http_response * add_char_to_code_description(struct http_response * ans, char c, size_t * code_description_current_length);
struct http_response * error(struct http_response * ans, http_response_parser_error_t error_type);

// definiciÃ³n de maquina

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
    ST_DATA, // Primer byte del data (transaction id 1)
    ST_SKIP_1, // transaction id 2
    ST_SKIP_2, // dns flags 1
    ST_SKIP_3, // dns flags 2
    ST_SKIP_4, // questions 1
    ST_SKIP_5, // questions 2
    ST_SKIP_6,
    ST_ANSWERS_QTY_1,
    ST_ANSWERS_QTY_2,
    ST_SKIP_7, // authority 1
    ST_SKIP_8, // authority 2
    ST_SKIP_9, // additional 1
    ST_SKIP_10, // additional 2
    ST_QUERY_NAME,
    ST_SKIP_11, // query type 1
    ST_SKIP_12, // query type 2
    ST_SKIP_13, // query class 1
    ST_SKIP_14, // query class 2
    ST_SKIP_15, // ans name 1,
    ST_SKIP_16, // ans name 2
    ST_SKIP_17, // ans type 1
    ST_SKIP_18, // ans type 2
    ST_SKIP_19, // ans class 1
    ST_SKIP_20, // ans class 2
    ST_TTL_1,
    ST_TTL_2,
    ST_TTL_3,
    ST_TTL_4,
    ST_DATA_LENGTH_0,
    ST_IP_4_ADDRESS_1,
    ST_IP_4_ADDRESS_2,
    ST_IP_4_ADDRESS_3,
    ST_IP_4_ADDRESS_4,
    ST_IP_6_ADDRESS_1,
    ST_IP_6_ADDRESS_2,
    ST_IP_6_ADDRESS_3,
    ST_IP_6_ADDRESS_4,
    ST_IP_6_ADDRESS_5,
    ST_IP_6_ADDRESS_6,
    ST_IP_6_ADDRESS_7,
    ST_IP_6_ADDRESS_8,
    ST_IP_6_ADDRESS_9,
    ST_IP_6_ADDRESS_10,
    ST_IP_6_ADDRESS_11,
    ST_IP_6_ADDRESS_12,
    ST_IP_6_ADDRESS_13,
    ST_IP_6_ADDRESS_14,
    ST_IP_6_ADDRESS_15,
    ST_IP_6_ADDRESS_16,
    ST_END_IP,
    ST_INVALID_INPUT_FORMAT,
};

enum event_type {
    SUCCESS,
    COPY_STATUS_1,
    COPY_STATUS_2,
    COPY_STATUS_3,
    COPY_STATUS_DESC,
    COPY_STATUS_DESC_R,
    END_COPY_STATUS_DESC,
    COPY_ANSWER_QTY_1,
    COPY_ANSWER_QTY_2,
    COPY_TTL_1,
    COPY_TTL_2,
    COPY_TTL_3,
    COPY_TTL_4,
    COPY_ADDR_4,
    COPY_ADDR_6,
    INVALID_INPUT_FORMAT_T,
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
copy_answer_qty_1(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_ANSWER_QTY_1;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_answer_qty_2(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_ANSWER_QTY_2;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_ttl_1(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_TTL_1;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_ttl_2(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_TTL_2;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_ttl_3(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_TTL_3;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_ttl_4(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_TTL_4;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_addr_4(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_ADDR_4;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
copy_addr_6(struct parser_event *ret, const uint8_t c) {
    ret->type    = COPY_ADDR_6;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
invalid_input(struct parser_event *ret, const uint8_t c) {
    ret->type    = INVALID_INPUT_FORMAT_T;
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

static const struct parser_state_transition STATUS_CODE_1 [] =  {
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

static const struct parser_state_transition STATUS_CODE_2 [] =  {
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

static const struct parser_state_transition STATUS_CODE_3 [] =  {
    {.when = ' ',        .dest = ST_CODE_DESC,                  .act1 = next_state,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
};

static const struct parser_state_transition CODE_DESC [] =  {
    {.when = '\r',       .dest = ST_CODE_DESC_POSSIBLE_END,     .act1 = next_state,},
    {.when = '\0',       .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
    {.when = ANY,        .dest = ST_CODE_DESC,                  .act1 = copy_status_desc,},
};

static const struct parser_state_transition CODE_DESC_POSSIBLE_END [] =  {
    {.when = '\n',       .dest = ST_HEADERS,                    .act1 = end_copy_status_desc,},
    {.when = '\0',       .dest = ST_INVALID_INPUT_FORMAT,       .act1 = invalid_input,},
    {.when = ANY,        .dest = ST_CODE_DESC,                  .act1 = copy_status_desc_r,},
};

static const struct parser_state_transition HEADERS [] =  {
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
    {.when = ANY,        .dest = ST_SKIP_1,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_1 [] =  {
    {.when = ANY,        .dest = ST_SKIP_2,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_2 [] =  {
    {.when = ANY,        .dest = ST_SKIP_3,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_3 [] =  {
    {.when = ANY,        .dest = ST_SKIP_4,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_4 [] =  {
    {.when = ANY,        .dest = ST_SKIP_5,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_5 [] =  {
    {.when = ANY,        .dest = ST_SKIP_6,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_6 [] =  {
    {.when = ANY,        .dest = ST_ANSWERS_QTY_1,               .act1 = copy_answer_qty_1,},
};

static const struct parser_state_transition ANSWERS_QTY_1 [] =  {
    {.when = ANY,        .dest = ST_ANSWERS_QTY_2,               .act1 = copy_answer_qty_2,},
};

static const struct parser_state_transition ANSWERS_QTY_2 [] =  {
    {.when = ANY,        .dest = ST_SKIP_7,                     .act1 = next_state,},
};

static const struct parser_state_transition SKIP_7 [] =  {
    {.when = ANY,        .dest = ST_SKIP_8,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_8 [] =  {
    {.when = ANY,        .dest = ST_SKIP_9,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_9 [] =  {
    {.when = ANY,        .dest = ST_SKIP_10,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_10 [] =  {
    {.when = '\0',        .dest = ST_SKIP_11,                       .act1 = next_state,},
    {.when = ANY,        .dest = ST_QUERY_NAME,                       .act1 = next_state,},
};

static const struct parser_state_transition QUERY_NAME [] =  {
    {.when = '\0',        .dest = ST_SKIP_10,                       .act1 = next_state,},
    {.when = ANY,        .dest = ST_QUERY_NAME,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_11 [] =  {
    {.when = ANY,        .dest = ST_SKIP_12,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_12 [] =  {
    {.when = ANY,        .dest = ST_SKIP_13,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_13 [] =  {
    {.when = ANY,        .dest = ST_SKIP_14,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_14 [] =  {
    {.when = ANY,        .dest = ST_SKIP_15,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_15 [] =  {
    {.when = ANY,        .dest = ST_SKIP_16,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_16 [] =  {
    {.when = ANY,        .dest = ST_SKIP_17,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_17 [] =  {
    {.when = ANY,        .dest = ST_SKIP_18,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_18 [] =  {
    {.when = ANY,        .dest = ST_SKIP_19,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_19 [] =  {
    {.when = ANY,        .dest = ST_SKIP_20,                       .act1 = next_state,},
};

static const struct parser_state_transition SKIP_20 [] =  {
    {.when = ANY,        .dest = ST_TTL_1,                       .act1 = copy_ttl_1,},
};

static const struct parser_state_transition TTL_1 [] =  {
    {.when = ANY,        .dest = ST_TTL_2,                       .act1 = copy_ttl_2,},
};

static const struct parser_state_transition TTL_2 [] =  {
    {.when = ANY,        .dest = ST_TTL_3,                       .act1 = copy_ttl_3,},
};

static const struct parser_state_transition TTL_3 [] =  {
    {.when = ANY,        .dest = ST_TTL_4,                       .act1 = copy_ttl_4,},
};

static const struct parser_state_transition TTL_4 [] =  {
    {.when = '\0',        .dest = ST_DATA_LENGTH_0,               .act1 = next_state,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,               .act1 = invalid_input,},
};

static const struct parser_state_transition DATA_LENGTH_0 [] =  {
    {.when = 4,          .dest = ST_IP_4_ADDRESS_1,               .act1 = next_state,},
    {.when = 16,         .dest = ST_IP_6_ADDRESS_1,               .act1 = next_state,},
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,         .act1 = invalid_input,},
};

static const struct parser_state_transition IP_4_ADDRESS_1 [] =  {
    {.when = ANY,        .dest = ST_IP_4_ADDRESS_2,               .act1 = copy_addr_4,},
};

static const struct parser_state_transition IP_4_ADDRESS_2 [] =  {
    {.when = ANY,        .dest = ST_IP_4_ADDRESS_3,               .act1 = copy_addr_4,},
};

static const struct parser_state_transition IP_4_ADDRESS_3 [] =  {
    {.when = ANY,        .dest = ST_IP_4_ADDRESS_4,               .act1 = copy_addr_4,},
};

static const struct parser_state_transition IP_4_ADDRESS_4 [] =  {
    {.when = ANY,        .dest = ST_END_IP,               .act1 = copy_addr_4,},
};

static const struct parser_state_transition IP_6_ADDRESS_1 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_2,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_2 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_3,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_3 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_4,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_4 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_5,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_5 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_6,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_6 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_7,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_7 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_8,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_8 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_9,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_9 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_10,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_10 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_11,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_11 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_12,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_12 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_13,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_13 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_14,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_14 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_15,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_15 [] =  {
    {.when = ANY,        .dest = ST_IP_6_ADDRESS_16,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition IP_6_ADDRESS_16 [] =  {
    {.when = ANY,        .dest = ST_END_IP,               .act1 = copy_addr_6,},
};

static const struct parser_state_transition END_IP [] =  {
    {.when = ANY,        .dest = ST_SKIP_15,               .act1 = next_state,},
};

static const struct parser_state_transition INVALID_INPUT_FORMAT [] =  {
    {.when = ANY,        .dest = ST_INVALID_INPUT_FORMAT,         .act1 = invalid_input,},
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
    STATUS_CODE_1,
    STATUS_CODE_2,
    STATUS_CODE_3,
    CODE_DESC,
    CODE_DESC_POSSIBLE_END,
    HEADERS,
    HEADER_POSSIBLE_END,
    HEADER_END,
    HEADERS_POSSIBLE_END,
    DATA, // Primer byte del data (transaction id 1)
    SKIP_1, // transaction id 2
    SKIP_2, // dns flags 1
    SKIP_3, // dns flags 2
    SKIP_4, // questions 1
    SKIP_5, // questions 2
    SKIP_6,
    ANSWERS_QTY_1,
    ANSWERS_QTY_2,
    SKIP_7, // authority 1
    SKIP_8, // authority 2
    SKIP_9, // additional 1
    SKIP_10, // additional 2
    QUERY_NAME,
    SKIP_11, // query type 1
    SKIP_12, // query type 2
    SKIP_13, // query class 1
    SKIP_14, // query class 2
    SKIP_15, // ans name 1,
    SKIP_16, // ans name 2
    SKIP_17, // ans type 1
    SKIP_18, // ans type 2
    SKIP_19, // ans class 1
    SKIP_20, 
    TTL_1,
    TTL_2,
    TTL_3,
    TTL_4,
    DATA_LENGTH_0,
    IP_4_ADDRESS_1,
    IP_4_ADDRESS_2,
    IP_4_ADDRESS_3,
    IP_4_ADDRESS_4,
    IP_6_ADDRESS_1,
    IP_6_ADDRESS_2,
    IP_6_ADDRESS_3,
    IP_6_ADDRESS_4,
    IP_6_ADDRESS_5,
    IP_6_ADDRESS_6,
    IP_6_ADDRESS_7,
    IP_6_ADDRESS_8,
    IP_6_ADDRESS_9,
    IP_6_ADDRESS_10,
    IP_6_ADDRESS_11,
    IP_6_ADDRESS_12,
    IP_6_ADDRESS_13,
    IP_6_ADDRESS_14,
    IP_6_ADDRESS_15,
    IP_6_ADDRESS_16,
    END_IP,
    INVALID_INPUT_FORMAT,
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
    N(STATUS_CODE_1),
    N(STATUS_CODE_2),
    N(STATUS_CODE_3),
    N(CODE_DESC),
    N(CODE_DESC_POSSIBLE_END),
    N(HEADERS),
    N(HEADER_POSSIBLE_END),
    N(HEADER_END),
    N(HEADERS_POSSIBLE_END),
    N(DATA),
    N(SKIP_1),
    N(SKIP_2),
    N(SKIP_3),
    N(SKIP_4),
    N(SKIP_5),
    N(SKIP_6),
    N(ANSWERS_QTY_1),
    N(ANSWERS_QTY_2),
    N(SKIP_7),
    N(SKIP_8),
    N(SKIP_9),
    N(SKIP_10),
    N(QUERY_NAME),
    N(SKIP_11),
    N(SKIP_12),
    N(SKIP_13),
    N(SKIP_14),
    N(SKIP_15),
    N(SKIP_16),
    N(SKIP_17),
    N(SKIP_18),
    N(SKIP_19),
    N(SKIP_20),
    N(TTL_1),
    N(TTL_2),
    N(TTL_3),
    N(TTL_4),
    N(DATA_LENGTH_0),
    N(IP_4_ADDRESS_1),
    N(IP_4_ADDRESS_2),
    N(IP_4_ADDRESS_3),
    N(IP_4_ADDRESS_4),
    N(IP_6_ADDRESS_1),
    N(IP_6_ADDRESS_2),
    N(IP_6_ADDRESS_3),
    N(IP_6_ADDRESS_4),
    N(IP_6_ADDRESS_5),
    N(IP_6_ADDRESS_6),
    N(IP_6_ADDRESS_7),
    N(IP_6_ADDRESS_8),
    N(IP_6_ADDRESS_9),
    N(IP_6_ADDRESS_10),
    N(IP_6_ADDRESS_11),
    N(IP_6_ADDRESS_12),
    N(IP_6_ADDRESS_13),
    N(IP_6_ADDRESS_14),
    N(IP_6_ADDRESS_15),
    N(IP_6_ADDRESS_16),
    N(END_IP),
    N(INVALID_INPUT_FORMAT),
};

static struct parser_definition definition = {
    .states_count = N(states),
    .states       = states,
    .states_n     = states_n,
    .start_state  = ST_START,
};

struct http_response * http_response_parser(uint8_t * s, size_t s_length){
    struct parser *parser = parser_init(parser_no_classes(), &definition);
    struct http_response * ans = calloc(1, sizeof(*ans));
    int answer_qty = 0;
    int ttl_length = 0;
    int current_ip_byte = 0;
    size_t code_description_current_length = 0;
    for(size_t i = 0; i < s_length; i++){
        const struct parser_event* ret = parser_feed(parser, s[i]);
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
                    parser_destroy(parser);
                    return error(ans, REALLOC_ERROR);
                }
            break;
            case COPY_ANSWER_QTY_1:
                answer_qty = ret->data[0] * 16;
            break;
            case COPY_ANSWER_QTY_2:
                answer_qty += ret->data[0];
                if(answer_qty > MAX_ADDR){
                    return error(ans, INVALID_INPUT_FORMAT_ERROR);
                }
                if(answer_qty == 0){
                    return ans;
                }
            break;
            case COPY_TTL_1:
                ans->ttl[ttl_length] = ret->data[0] * 512; // 8^3
            break;
            case COPY_TTL_2:
                ans->ttl[ttl_length] += ret->data[0] * 64; // 8^2
            break;
            case COPY_TTL_3:
                ans->ttl[ttl_length] += ret->data[0] * 8; // 8^1
            break;
            case COPY_TTL_4:
                ans->ttl[ttl_length++] += ret->data[0]; // 8^0
            break;
            case COPY_ADDR_4:
                if(ans->ipv4_qty >= answer_qty){
                    parser_destroy(parser);
                    return error(ans, INVALID_INPUT_FORMAT_ERROR);
                }
                ans->ipv4_addr[ans->ipv4_qty].byte[current_ip_byte++] = ret->data[0];
                if(current_ip_byte == IP_4_BYTES){
                    current_ip_byte = 0;
                    (ans->ipv4_qty)++;
                }
            break;
            case COPY_ADDR_6:
                if(ans->ipv6_qty >= answer_qty){
                        parser_destroy(parser);
                        return error(ans, INVALID_INPUT_FORMAT_ERROR);
                }
                ans->ipv6_addr[ans->ipv6_qty].byte[current_ip_byte++] = ret->data[0];
                if(current_ip_byte == IP_6_BYTES){
                    current_ip_byte = 0;
                    (ans->ipv6_qty)++;
                }
            break;
            case INVALID_INPUT_FORMAT_T:
                parser_destroy(parser);
                return error(ans, INVALID_INPUT_FORMAT_ERROR);
            break;
        }
    }
    parser_destroy(parser);
    if(ans->ipv4_qty > 0 && current_ip_byte != 0){
        return error(ans, INVALID_INPUT_FORMAT_ERROR);
    }
    if (ans->ipv6_qty > 0 && current_ip_byte != 0){
        return error(ans, INVALID_INPUT_FORMAT_ERROR);
    }
    return ans;
}

void free_http_response(struct http_response * ans){
    if(ans != NULL){
        if(ans->code_description != NULL){
            free(ans->code_description);
        }
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

struct http_response * error(struct http_response * ans, http_response_parser_error_t error_type){
    free_http_response(ans);
    ans = calloc(1, sizeof(*ans));
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
        buffer[i] = (uint8_t)c;
        i++;
    }
    fclose(fp);
    buffer = realloc(buffer, i * sizeof(*buffer));

    struct http_response * ans = http_response_parser(buffer, i);
    printf("%d\n", ans->status_code);
    printf("%s\n", ans->code_description);
    printf("IP V4: %d\n", ans->ipv4_qty);
    for(int i=0; i<ans->ipv4_qty; i++){
        for(int j=0; j<IP_4_BYTES; j++){
            printf("%d.", ans->ipv4_addr[i].byte[j]);
        }
        printf("\n");
        printf("TTL: %d secs\n", ans->ttl[i]);
    }
    printf("IP V6: %d\n", ans->ipv6_qty);
    for(int i=0; i<ans->ipv6_qty; i++){
        for(int j=0; j<IP_6_BYTES; j+=2){
            printf("%02X%02X:", ans->ipv6_addr[i].byte[j], ans->ipv6_addr[i].byte[j+1]);
        }
        printf("\n");
        printf("TTL: %d secs\n", ans->ttl[i]);

    }
    free_http_response(ans);
    free(buffer);
    return 0;
}
*/