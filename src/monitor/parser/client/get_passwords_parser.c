#include <stdio.h>
#include <stdlib.h>

#include "../../../utils/parser.h"
#include "get_passwords_parser.h"

#define CHUNK_SIZE 10

/* Funciones auxiliares */
void *resize_if_needed(void *ptr, size_t ptr_size, size_t current_length);

struct passwords *error(struct passwords *ans, parser_error_t error_type);

parser_error_t add_to_string(char ** s, uint8_t c, size_t * current_length);

// definición de maquina

enum states {
    ST_YEAR_1,
    ST_YEAR_2,
    ST_YEAR_3,
    ST_YEAR_4,
    ST_DASH_1,
    ST_MONTH_1,
    ST_MONTH_2_0,
    ST_MONTH_2_1,
    ST_DASH_2_29,
    ST_DASH_2_30,
    ST_DASH_2_31,
    ST_DAY_1_29,
    ST_DAY_2_29,
    ST_DAY_1_30,
    ST_DAY_2_30,
    ST_DAY_2_30_3,
    ST_DAY_1_31,
    ST_DAY_2_31,
    ST_DAY_2_31_3,
    ST_T,
    ST_HOUR_1,
    ST_HOUR_2,
    ST_HOUR_2_2,
    ST_COLON_1,
    ST_MINUTE_1,
    ST_MINUTE_2,
    ST_COLON_2,
    ST_SECOND_1,
    ST_SECOND_2,
    ST_TIMEZONE,
    ST_TIMEZONE_1,
    ST_TIMEZONE_2,
    ST_TIMEZONE_COLON,
    ST_TIMEZONE_3,
    ST_TIMEZONE_4,
    ST_END_TIME,
    ST_USER,
    ST_P,
    ST_P_END,
    ST_PROTOCOL,
    ST_DESTINATION,
    ST_DPORT,
    ST_USERNAME,
    ST_PASSWORD,
    ST_END_ENTRY,
    ST_END,
    ST_INVALID_INPUT_FORMAT,
};

enum event_type {
    SUCCESS,
    COPY_TIME,
    COPY_USER,
    COPY_PROTOCOL,
    COPY_DESTINATION,
    COPY_DPORT,
    COPY_USERNAME,
    COPY_PASSWORD,
    END_ENTRY_T,
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
copy_time(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_TIME;
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
copy_protocol(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_PROTOCOL;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_destination(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_DESTINATION;
    ret->n = 1;
    ret->data[0] = c;
}

static void
copy_dport(struct parser_event *ret, const uint8_t c) {
    ret->type = COPY_DPORT;
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
end_entry(struct parser_event *ret, const uint8_t c) {
    ret->type = END_ENTRY_T;
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

static const struct parser_state_transition YEAR_1[] = {
    {.when = '\0', .dest = ST_END, .act1 = end,},
    {.when = '0', .dest = ST_YEAR_2, .act1 = copy_time,},
    {.when = '1', .dest = ST_YEAR_2, .act1 = copy_time,},
    {.when = '2', .dest = ST_YEAR_2, .act1 = copy_time,},
    {.when = '3', .dest = ST_YEAR_2, .act1 = copy_time,},
    {.when = '4', .dest = ST_YEAR_2, .act1 = copy_time,},
    {.when = '5', .dest = ST_YEAR_2, .act1 = copy_time,},
    {.when = '6', .dest = ST_YEAR_2, .act1 = copy_time,},
    {.when = '7', .dest = ST_YEAR_2, .act1 = copy_time,},
    {.when = '8', .dest = ST_YEAR_2, .act1 = copy_time,},
    {.when = '9', .dest = ST_YEAR_2, .act1 = copy_time,},
    {.when = ANY, .dest = INVALID_INPUT_FORMAT_T, .act1 = invalid_input,},
};

static const struct parser_state_transition YEAR_2[] = {
    {.when = '0', .dest = ST_YEAR_3, .act1 = copy_time,},
    {.when = '1', .dest = ST_YEAR_3, .act1 = copy_time,},
    {.when = '2', .dest = ST_YEAR_3, .act1 = copy_time,},
    {.when = '3', .dest = ST_YEAR_3, .act1 = copy_time,},
    {.when = '4', .dest = ST_YEAR_3, .act1 = copy_time,},
    {.when = '5', .dest = ST_YEAR_3, .act1 = copy_time,},
    {.when = '6', .dest = ST_YEAR_3, .act1 = copy_time,},
    {.when = '7', .dest = ST_YEAR_3, .act1 = copy_time,},
    {.when = '8', .dest = ST_YEAR_3, .act1 = copy_time,},
    {.when = '9', .dest = ST_YEAR_3, .act1 = copy_time,},
    {.when = ANY, .dest = INVALID_INPUT_FORMAT_T, .act1 = invalid_input,},
};

static const struct parser_state_transition YEAR_3[] = {
    {.when = '0', .dest = ST_YEAR_4, .act1 = copy_time,},
    {.when = '1', .dest = ST_YEAR_4, .act1 = copy_time,},
    {.when = '2', .dest = ST_YEAR_4, .act1 = copy_time,},
    {.when = '3', .dest = ST_YEAR_4, .act1 = copy_time,},
    {.when = '4', .dest = ST_YEAR_4, .act1 = copy_time,},
    {.when = '5', .dest = ST_YEAR_4, .act1 = copy_time,},
    {.when = '6', .dest = ST_YEAR_4, .act1 = copy_time,},
    {.when = '7', .dest = ST_YEAR_4, .act1 = copy_time,},
    {.when = '8', .dest = ST_YEAR_4, .act1 = copy_time,},
    {.when = '9', .dest = ST_YEAR_4, .act1 = copy_time,},
    {.when = ANY, .dest = INVALID_INPUT_FORMAT_T, .act1 = invalid_input,},
};

static const struct parser_state_transition YEAR_4[] = {
    {.when = '0', .dest = ST_DASH_1, .act1 = copy_time,},
    {.when = '1', .dest = ST_DASH_1, .act1 = copy_time,},
    {.when = '2', .dest = ST_DASH_1, .act1 = copy_time,},
    {.when = '3', .dest = ST_DASH_1, .act1 = copy_time,},
    {.when = '4', .dest = ST_DASH_1, .act1 = copy_time,},
    {.when = '5', .dest = ST_DASH_1, .act1 = copy_time,},
    {.when = '6', .dest = ST_DASH_1, .act1 = copy_time,},
    {.when = '7', .dest = ST_DASH_1, .act1 = copy_time,},
    {.when = '8', .dest = ST_DASH_1, .act1 = copy_time,},
    {.when = '9', .dest = ST_DASH_1, .act1 = copy_time,},
    {.when = ANY, .dest = INVALID_INPUT_FORMAT_T, .act1 = invalid_input,},
};

static const struct parser_state_transition DASH_1[] = {
    {.when = '-', .dest = ST_MONTH_1, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition MONTH_1[] = {
    {.when = '0', .dest = ST_MONTH_2_0, .act1 = copy_time,},
    {.when = '1', .dest = ST_MONTH_2_1, .act1 = copy_time,},
    {.when = ANY, .dest = INVALID_INPUT_FORMAT_T, .act1 = invalid_input,},
};

static const struct parser_state_transition MONTH_2_0[] = {
    {.when = '1', .dest = ST_DASH_2_31, .act1 = copy_time,}, // Enero
    {.when = '2', .dest = ST_DASH_2_29, .act1 = copy_time,}, // Febrero
    {.when = '3', .dest = ST_DASH_2_31, .act1 = copy_time,}, // Marzo
    {.when = '4', .dest = ST_DASH_2_30, .act1 = copy_time,}, // Abril
    {.when = '5', .dest = ST_DASH_2_31, .act1 = copy_time,}, // Mayo
    {.when = '6', .dest = ST_DASH_2_30, .act1 = copy_time,}, // Junio
    {.when = '7', .dest = ST_DASH_2_31, .act1 = copy_time,}, // Julio
    {.when = '8', .dest = ST_DASH_2_31, .act1 = copy_time,}, // Agosto
    {.when = '9', .dest = ST_DASH_2_30, .act1 = copy_time,}, // Septiembre
    {.when = ANY, .dest = INVALID_INPUT_FORMAT_T, .act1 = invalid_input,},
};

static const struct parser_state_transition MONTH_2_1[] = {
    {.when = '0', .dest = ST_DASH_2_31, .act1 = copy_time,}, // Octubre
    {.when = '1', .dest = ST_DASH_2_30, .act1 = copy_time,}, // Noviembre
    {.when = '2', .dest = ST_DASH_2_31, .act1 = copy_time,}, // Diciembre
    {.when = ANY, .dest = INVALID_INPUT_FORMAT_T, .act1 = invalid_input,},
};

static const struct parser_state_transition DASH_2_29[] = {
    {.when = '-', .dest = ST_DAY_1_29, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition DASH_2_30[] = {
    {.when = '-', .dest = ST_DAY_1_30, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition DASH_2_31[] = {
    {.when = '-', .dest = ST_DAY_1_31, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition DAY_1_29[] = {
    {.when = '0', .dest = ST_DAY_2_29, .act1 = copy_time,},
    {.when = '1', .dest = ST_DAY_2_29, .act1 = copy_time,},
    {.when = '2', .dest = ST_DAY_2_29, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition DAY_1_30[] = {
    {.when = '0', .dest = ST_DAY_2_30, .act1 = copy_time,},
    {.when = '1', .dest = ST_DAY_2_30, .act1 = copy_time,},
    {.when = '2', .dest = ST_DAY_2_30, .act1 = copy_time,},
    {.when = '3', .dest = ST_DAY_2_30_3, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition DAY_1_31[] = {
    {.when = '0', .dest = ST_DAY_2_31, .act1 = copy_time,},
    {.when = '1', .dest = ST_DAY_2_31, .act1 = copy_time,},
    {.when = '2', .dest = ST_DAY_2_31, .act1 = copy_time,},
    {.when = '3', .dest = ST_DAY_2_31_3, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition DAY_2_29[] = {
    {.when = '0', .dest = ST_T, .act1 = copy_time,},
    {.when = '1', .dest = ST_T, .act1 = copy_time,},
    {.when = '2', .dest = ST_T, .act1 = copy_time,},
    {.when = '3', .dest = ST_T, .act1 = copy_time,},
    {.when = '4', .dest = ST_T, .act1 = copy_time,},
    {.when = '5', .dest = ST_T, .act1 = copy_time,},
    {.when = '6', .dest = ST_T, .act1 = copy_time,},
    {.when = '7', .dest = ST_T, .act1 = copy_time,},
    {.when = '8', .dest = ST_T, .act1 = copy_time,},
    {.when = '9', .dest = ST_T, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition DAY_2_30[] = {
    {.when = '0', .dest = ST_T, .act1 = copy_time,},
    {.when = '1', .dest = ST_T, .act1 = copy_time,},
    {.when = '2', .dest = ST_T, .act1 = copy_time,},
    {.when = '3', .dest = ST_T, .act1 = copy_time,},
    {.when = '4', .dest = ST_T, .act1 = copy_time,},
    {.when = '5', .dest = ST_T, .act1 = copy_time,},
    {.when = '6', .dest = ST_T, .act1 = copy_time,},
    {.when = '7', .dest = ST_T, .act1 = copy_time,},
    {.when = '8', .dest = ST_T, .act1 = copy_time,},
    {.when = '9', .dest = ST_T, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition DAY_2_30_3[] = {
    {.when = '0', .dest = ST_T, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition DAY_2_31[] = {
    {.when = '0', .dest = ST_T, .act1 = copy_time,},
    {.when = '1', .dest = ST_T, .act1 = copy_time,},
    {.when = '2', .dest = ST_T, .act1 = copy_time,},
    {.when = '3', .dest = ST_T, .act1 = copy_time,},
    {.when = '4', .dest = ST_T, .act1 = copy_time,},
    {.when = '5', .dest = ST_T, .act1 = copy_time,},
    {.when = '6', .dest = ST_T, .act1 = copy_time,},
    {.when = '7', .dest = ST_T, .act1 = copy_time,},
    {.when = '8', .dest = ST_T, .act1 = copy_time,},
    {.when = '9', .dest = ST_T, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition DAY_2_31_3[] = {
    {.when = '0', .dest = ST_T, .act1 = copy_time,},
    {.when = '1', .dest = ST_T, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition T[] = {
    {.when = 'T', .dest = ST_HOUR_1, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition HOUR_1[] = {
    {.when = '0', .dest = ST_HOUR_2, .act1 = copy_time,},
    {.when = '1', .dest = ST_HOUR_2, .act1 = copy_time,},
    {.when = '2', .dest = ST_HOUR_2_2, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition HOUR_2[] = {
    {.when = '0', .dest = ST_COLON_1, .act1 = copy_time,},
    {.when = '1', .dest = ST_COLON_1, .act1 = copy_time,},
    {.when = '2', .dest = ST_COLON_1, .act1 = copy_time,},
    {.when = '3', .dest = ST_COLON_1, .act1 = copy_time,},
    {.when = '4', .dest = ST_COLON_1, .act1 = copy_time,},
    {.when = '5', .dest = ST_COLON_1, .act1 = copy_time,},
    {.when = '6', .dest = ST_COLON_1, .act1 = copy_time,},
    {.when = '7', .dest = ST_COLON_1, .act1 = copy_time,},
    {.when = '8', .dest = ST_COLON_1, .act1 = copy_time,},
    {.when = '9', .dest = ST_COLON_1, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition HOUR_2_2[] = {
    {.when = '0', .dest = ST_COLON_1, .act1 = copy_time,},
    {.when = '1', .dest = ST_COLON_1, .act1 = copy_time,},
    {.when = '2', .dest = ST_COLON_1, .act1 = copy_time,},
    {.when = '3', .dest = ST_COLON_1, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition COLON_1[] = {
    {.when = ':', .dest = ST_MINUTE_1, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition MINUTE_1[] = {
    {.when = '0', .dest = ST_MINUTE_2, .act1 = copy_time,},
    {.when = '1', .dest = ST_MINUTE_2, .act1 = copy_time,},
    {.when = '2', .dest = ST_MINUTE_2, .act1 = copy_time,},
    {.when = '3', .dest = ST_MINUTE_2, .act1 = copy_time,},
    {.when = '4', .dest = ST_MINUTE_2, .act1 = copy_time,},
    {.when = '5', .dest = ST_MINUTE_2, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition MINUTE_2[] = {
    {.when = '0', .dest = ST_COLON_2, .act1 = copy_time,},
    {.when = '1', .dest = ST_COLON_2, .act1 = copy_time,},
    {.when = '2', .dest = ST_COLON_2, .act1 = copy_time,},
    {.when = '3', .dest = ST_COLON_2, .act1 = copy_time,},
    {.when = '4', .dest = ST_COLON_2, .act1 = copy_time,},
    {.when = '5', .dest = ST_COLON_2, .act1 = copy_time,},
    {.when = '6', .dest = ST_COLON_2, .act1 = copy_time,},
    {.when = '7', .dest = ST_COLON_2, .act1 = copy_time,},
    {.when = '8', .dest = ST_COLON_2, .act1 = copy_time,},
    {.when = '9', .dest = ST_COLON_2, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition COLON_2[] = {
    {.when = ':', .dest = ST_SECOND_1, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition SECOND_1[] = {
    {.when = '0', .dest = ST_SECOND_2, .act1 = copy_time,},
    {.when = '1', .dest = ST_SECOND_2, .act1 = copy_time,},
    {.when = '2', .dest = ST_SECOND_2, .act1 = copy_time,},
    {.when = '3', .dest = ST_SECOND_2, .act1 = copy_time,},
    {.when = '4', .dest = ST_SECOND_2, .act1 = copy_time,},
    {.when = '5', .dest = ST_SECOND_2, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition SECOND_2[] = {
    {.when = '0', .dest = ST_TIMEZONE, .act1 = copy_time,},
    {.when = '1', .dest = ST_TIMEZONE, .act1 = copy_time,},
    {.when = '2', .dest = ST_TIMEZONE, .act1 = copy_time,},
    {.when = '3', .dest = ST_TIMEZONE, .act1 = copy_time,},
    {.when = '4', .dest = ST_TIMEZONE, .act1 = copy_time,},
    {.when = '5', .dest = ST_TIMEZONE, .act1 = copy_time,},
    {.when = '6', .dest = ST_TIMEZONE, .act1 = copy_time,},
    {.when = '7', .dest = ST_TIMEZONE, .act1 = copy_time,},
    {.when = '8', .dest = ST_TIMEZONE, .act1 = copy_time,},
    {.when = '9', .dest = ST_TIMEZONE, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition TIMEZONE[] = {
    {.when = 'Z', .dest = ST_END_TIME, .act1 = copy_time,},
    {.when = '+', .dest = ST_TIMEZONE_1, .act1 = copy_time,},
    {.when = '-', .dest = ST_TIMEZONE_1, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition TIMEZONE_1[] = {
    {.when = '0', .dest = ST_TIMEZONE_2, .act1 = copy_time,},
    {.when = '1', .dest = ST_TIMEZONE_2, .act1 = copy_time,},
    {.when = '2', .dest = ST_TIMEZONE_2, .act1 = copy_time,},
    {.when = '3', .dest = ST_TIMEZONE_2, .act1 = copy_time,},
    {.when = '4', .dest = ST_TIMEZONE_2, .act1 = copy_time,},
    {.when = '5', .dest = ST_TIMEZONE_2, .act1 = copy_time,},
    {.when = '6', .dest = ST_TIMEZONE_2, .act1 = copy_time,},
    {.when = '7', .dest = ST_TIMEZONE_2, .act1 = copy_time,},
    {.when = '8', .dest = ST_TIMEZONE_2, .act1 = copy_time,},
    {.when = '9', .dest = ST_TIMEZONE_2, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition TIMEZONE_2[] = {
    {.when = '0', .dest = ST_TIMEZONE_3, .act1 = copy_time,},
    {.when = '1', .dest = ST_TIMEZONE_3, .act1 = copy_time,},
    {.when = '2', .dest = ST_TIMEZONE_3, .act1 = copy_time,},
    {.when = '3', .dest = ST_TIMEZONE_3, .act1 = copy_time,},
    {.when = '4', .dest = ST_TIMEZONE_3, .act1 = copy_time,},
    {.when = '5', .dest = ST_TIMEZONE_3, .act1 = copy_time,},
    {.when = '6', .dest = ST_TIMEZONE_3, .act1 = copy_time,},
    {.when = '7', .dest = ST_TIMEZONE_3, .act1 = copy_time,},
    {.when = '8', .dest = ST_TIMEZONE_3, .act1 = copy_time,},
    {.when = '9', .dest = ST_TIMEZONE_3, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition TIMEZONE_COLON[] = {
    {.when = '0', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '1', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '2', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '3', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '4', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '5', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '6', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '7', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '8', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '9', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition TIMEZONE_3[] = {
    {.when = '\0', .dest = ST_USER, .act1 = copy_time,},
    {.when = ':', .dest = ST_TIMEZONE_COLON, .act1 = copy_time,},
    {.when = '0', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '1', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '2', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '3', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '4', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '5', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '6', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '7', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '8', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = '9', .dest = ST_TIMEZONE_4, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition TIMEZONE_4[] = {
    {.when = '0', .dest = ST_END_TIME, .act1 = copy_time,},
    {.when = '1', .dest = ST_END_TIME, .act1 = copy_time,},
    {.when = '2', .dest = ST_END_TIME, .act1 = copy_time,},
    {.when = '3', .dest = ST_END_TIME, .act1 = copy_time,},
    {.when = '4', .dest = ST_END_TIME, .act1 = copy_time,},
    {.when = '5', .dest = ST_END_TIME, .act1 = copy_time,},
    {.when = '6', .dest = ST_END_TIME, .act1 = copy_time,},
    {.when = '7', .dest = ST_END_TIME, .act1 = copy_time,},
    {.when = '8', .dest = ST_END_TIME, .act1 = copy_time,},
    {.when = '9', .dest = ST_END_TIME, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition END_TIME[] = {
    {.when = '\0', .dest = ST_USER, .act1 = copy_time,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition USER[] = {
    {.when = '\0', .dest = ST_P, .act1 = copy_user,},
    {.when = ANY, .dest = ST_USER, .act1 = copy_user,},
};

static const struct parser_state_transition P[] = {
    {.when = 'P', .dest = ST_P_END, .act1 = next_state,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition P_END[] = {
    {.when = '\0', .dest = ST_PROTOCOL, .act1 = next_state,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition PROTOCOL[] = {
    {.when = '\0', .dest = ST_DESTINATION, .act1 = copy_protocol,},
    {.when = ANY, .dest = ST_PROTOCOL, .act1 = copy_protocol,},
};

static const struct parser_state_transition DESTINATION[] = {
    {.when = '\0', .dest = ST_DPORT, .act1 = copy_destination,},
    {.when = ANY, .dest = ST_DESTINATION, .act1 = copy_destination,},
};

static const struct parser_state_transition DPORT[] = {
    {.when = '\0', .dest = ST_USERNAME, .act1 = next_state,},
    {.when = '0', .dest = ST_DPORT, .act1 = copy_dport,},
    {.when = '1', .dest = ST_DPORT, .act1 = copy_dport,},
    {.when = '2', .dest = ST_DPORT, .act1 = copy_dport,},
    {.when = '3', .dest = ST_DPORT, .act1 = copy_dport,},
    {.when = '4', .dest = ST_DPORT, .act1 = copy_dport,},
    {.when = '5', .dest = ST_DPORT, .act1 = copy_dport,},
    {.when = '6', .dest = ST_DPORT, .act1 = copy_dport,},
    {.when = '7', .dest = ST_DPORT, .act1 = copy_dport,},
    {.when = '8', .dest = ST_DPORT, .act1 = copy_dport,},
    {.when = '9', .dest = ST_DPORT, .act1 = copy_dport,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition USERNAME[] = {
    {.when = '\0', .dest = ST_PASSWORD, .act1 = copy_username,},
    {.when = ANY, .dest = ST_USERNAME, .act1 = copy_username,},
};

static const struct parser_state_transition PASSWORD[] = {
    {.when = '\0', .dest = ST_END_ENTRY, .act1 = copy_password,},
    {.when = ANY, .dest = ST_PASSWORD, .act1 = copy_password,},
};

static const struct parser_state_transition END_ENTRY[] = {
    {.when = '\0', .dest = ST_YEAR_1, .act1 = end_entry,},
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition END[] = {
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition INVALID_INPUT_FORMAT[] = {
    {.when = ANY, .dest = ST_INVALID_INPUT_FORMAT, .act1 = invalid_input,},
};

static const struct parser_state_transition *states[] = {
    YEAR_1,
    YEAR_2,
    YEAR_3,
    YEAR_4,
    DASH_1,
    MONTH_1,
    MONTH_2_0,
    MONTH_2_1,
    DASH_2_29,
    DASH_2_30,
    DASH_2_31,
    DAY_1_29,
    DAY_2_29,
    DAY_1_30,
    DAY_2_30,
    DAY_2_30_3,
    DAY_1_31,
    DAY_2_31,
    DAY_2_31_3,
    T,
    HOUR_1,
    HOUR_2,
    HOUR_2_2,
    COLON_1,
    MINUTE_1,
    MINUTE_2,
    COLON_2,
    SECOND_1,
    SECOND_2,
    TIMEZONE,
    TIMEZONE_1,
    TIMEZONE_2,
    TIMEZONE_COLON,
    TIMEZONE_3,
    TIMEZONE_4,
    END_TIME,
    USER,
    P,
    P_END,
    PROTOCOL,
    DESTINATION,
    DPORT,
    USERNAME,
    PASSWORD,
    END_ENTRY,
    END,
    INVALID_INPUT_FORMAT,
};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t states_n[] = {
    N(YEAR_1),
    N(YEAR_2),
    N(YEAR_3),
    N(YEAR_4),
    N(DASH_1),
    N(MONTH_1),
    N(MONTH_2_0),
    N(MONTH_2_1),
    N(DASH_2_29),
    N(DASH_2_30),
    N(DASH_2_31),
    N(DAY_1_29),
    N(DAY_2_29),
    N(DAY_1_30),
    N(DAY_2_30),
    N(DAY_2_30_3),
    N(DAY_1_31),
    N(DAY_2_31),
    N(DAY_2_31_3),
    N(T),
    N(HOUR_1),
    N(HOUR_2),
    N(HOUR_2_2),
    N(COLON_1),
    N(MINUTE_1),
    N(MINUTE_2),
    N(COLON_2),
    N(SECOND_1),
    N(SECOND_2),
    N(TIMEZONE),
    N(TIMEZONE_1),
    N(TIMEZONE_2),
    N(TIMEZONE_COLON),
    N(TIMEZONE_3),
    N(TIMEZONE_4),
    N(END_TIME),
    N(USER),
    N(P),
    N(P_END),
    N(PROTOCOL),
    N(DESTINATION),
    N(DPORT),
    N(USERNAME),
    N(PASSWORD),
    N(END_ENTRY),
    N(END),
    N(INVALID_INPUT_FORMAT),
};

static struct parser_definition definition = {
        .states_count = N(states),
        .states       = states,
        .states_n     = states_n,
        .start_state  = ST_YEAR_1,
};

struct passwords * get_passwords_parser(uint8_t *s, size_t length) {
    struct passwords * ans = calloc(1, sizeof(*ans));
    struct parser *parser = parser_init(parser_no_classes(), &definition);
    size_t current_time_length = 0;
    size_t current_user_length = 0;
    size_t current_protocol_length = 0;
    size_t current_destination_length = 0;
    size_t current_username_length = 0;
    size_t current_password_length = 0;
    parser_error_t ans_error = NO_ERROR;
    int finished = 0;
    ans->entries = resize_if_needed(ans->entries, sizeof(*ans->entries), ans->entry_qty);
    ans->entries[ans->entry_qty].time = NULL;
    ans->entries[ans->entry_qty].user = NULL;
    ans->entries[ans->entry_qty].protocol = NULL;
    ans->entries[ans->entry_qty].destination = NULL;
    ans->entries[ans->entry_qty].destination_port = 0;
    ans->entries[ans->entry_qty].username = NULL;
    ans->entries[ans->entry_qty].password = NULL;
    for (size_t i = 0; i<length; i++) {
        const struct parser_event* ret = parser_feed(parser, s[i]);
        switch (ret->type) {
            case COPY_TIME:
                ans_error = add_to_string(&(ans->entries[ans->entry_qty].time), s[i], &current_time_length);
                if(ans_error != NO_ERROR){
                    if(ans->entries[ans->entry_qty].time != NULL){
                        free(ans->entries[ans->entry_qty].time);
                    }
                    parser_destroy(parser);
                    return error(ans, ans_error);
                }
            break;
            case COPY_USER:
                ans_error = add_to_string(&(ans->entries[ans->entry_qty].user), s[i], &current_user_length);
                if(ans_error != NO_ERROR){
                    if(ans->entries[ans->entry_qty].user != NULL){
                        free(ans->entries[ans->entry_qty].time);
                        free(ans->entries[ans->entry_qty].user);
                    }
                    parser_destroy(parser);
                    return error(ans, ans_error);
                }
            break;
            case COPY_PROTOCOL:
                ans_error = add_to_string(&(ans->entries[ans->entry_qty].protocol), s[i], &current_protocol_length);
                if(ans_error != NO_ERROR){
                    if(ans->entries[ans->entry_qty].protocol != NULL){
                        free(ans->entries[ans->entry_qty].time);
                        free(ans->entries[ans->entry_qty].user);
                        free(ans->entries[ans->entry_qty].protocol);
                    }
                    parser_destroy(parser);
                    return error(ans, ans_error);
                }
            break;
            case COPY_DESTINATION:
                ans_error = add_to_string(&(ans->entries[ans->entry_qty].destination), s[i], &current_destination_length);
                if(ans_error != NO_ERROR){
                    if(ans->entries[ans->entry_qty].destination != NULL){
                        free(ans->entries[ans->entry_qty].time);
                        free(ans->entries[ans->entry_qty].user);
                        free(ans->entries[ans->entry_qty].protocol);
                        free(ans->entries[ans->entry_qty].destination);
                    }
                    parser_destroy(parser);
                    return error(ans, ans_error);
                }
            break;
            case COPY_DPORT:
                ans->entries[ans->entry_qty].destination_port *= 10;
                ans->entries[ans->entry_qty].destination_port += s[i] - '0';
            break;
            case COPY_USERNAME:
                ans_error = add_to_string(&(ans->entries[ans->entry_qty].username), s[i], &current_username_length);
                if(ans_error != NO_ERROR){
                    if(ans->entries[ans->entry_qty].username != NULL){
                        free(ans->entries[ans->entry_qty].time);
                        free(ans->entries[ans->entry_qty].user);
                        free(ans->entries[ans->entry_qty].protocol);
                        free(ans->entries[ans->entry_qty].destination);
                        free(ans->entries[ans->entry_qty].username);
                    }
                    parser_destroy(parser);
                    return error(ans, ans_error);
                }
            break;
            case COPY_PASSWORD:
                ans_error = add_to_string(&(ans->entries[ans->entry_qty].password), s[i], &current_password_length);
                if(ans_error != NO_ERROR){
                    if(ans->entries[ans->entry_qty].username != NULL){
                        free(ans->entries[ans->entry_qty].time);
                        free(ans->entries[ans->entry_qty].user);
                        free(ans->entries[ans->entry_qty].protocol);
                        free(ans->entries[ans->entry_qty].destination);
                        free(ans->entries[ans->entry_qty].username);
                        free(ans->entries[ans->entry_qty].password);
                    }
                    parser_destroy(parser);
                    return error(ans, ans_error);
                }
            break;
            case END_ENTRY_T:
                current_time_length = 0;
                current_user_length = 0;
                current_protocol_length = 0;
                current_destination_length = 0;
                current_username_length = 0;
                current_password_length = 0;
                (ans->entry_qty)++;
                ans->entries = resize_if_needed(ans->entries, sizeof(*ans->entries), ans->entry_qty);
                ans->entries[ans->entry_qty].time = NULL;
                ans->entries[ans->entry_qty].user = NULL;
                ans->entries[ans->entry_qty].protocol = NULL;
                ans->entries[ans->entry_qty].destination = NULL;
                ans->entries[ans->entry_qty].destination_port = 0;
                ans->entries[ans->entry_qty].username = NULL;
                ans->entries[ans->entry_qty].password = NULL;
            break;
            case END_T:
                ans->entries = realloc(ans->entries, sizeof(*(ans->entries)) * ans->entry_qty);
                if(ans->entries == NULL){
                    parser_destroy(parser);
                    return error(ans, REALLOC_ERROR);
                }
                finished = 1;
            break;
            case INVALID_INPUT_FORMAT_T:
                if(ans->entries[ans->entry_qty].time != NULL){
                    free(ans->entries[ans->entry_qty].time);
                    if(ans->entries[ans->entry_qty].user != NULL){
                        free(ans->entries[ans->entry_qty].user);
                        if(ans->entries[ans->entry_qty].protocol != NULL){
                            free(ans->entries[ans->entry_qty].protocol);
                            if(ans->entries[ans->entry_qty].destination != NULL){
                                free(ans->entries[ans->entry_qty].destination);
                                if(ans->entries[ans->entry_qty].username != NULL){
                                    free(ans->entries[ans->entry_qty].username);
                                    if(ans->entries[ans->entry_qty].password != NULL){
                                        free(ans->entries[ans->entry_qty].password);
                                    }
                                }
                            }
                        }
                    }
                }
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

void free_passwords(struct passwords *passwords) {
    if (passwords != NULL) {
        if(passwords->entries != NULL){
            for(int i = 0; i<passwords->entry_qty; i++){
                free(passwords->entries[i].time);
                free(passwords->entries[i].user);
                free(passwords->entries[i].protocol);
                free(passwords->entries[i].destination);
                free(passwords->entries[i].username);
                free(passwords->entries[i].password);
            }
            free(passwords->entries);
        }
        free(passwords);
    }
}

struct passwords *error(struct passwords *ans, parser_error_t error_type) {
    free_passwords(ans);
    ans = calloc(1, sizeof(*ans));
    ans->error = error_type;
    return ans;
}

parser_error_t add_to_string(char ** s, uint8_t c, size_t * current_length){
    *s = resize_if_needed(*s, sizeof(**s), *current_length);
    if(*s == NULL){
        return REALLOC_ERROR;
    }
    (*s)[*current_length] = c;
    (*current_length)++;
    return NO_ERROR;
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
 *     3. Run in the terminal "afl-clang get_access_log_parser.c parser.c -o get_access_log_parser -pedantic -std=c99" (or afl-gcc)
 *     4. Run in the terminal "afl-fuzz -i parser_test_case -o afl-output -- ./get_access_log_parser @@"
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

    struct passwords * ans = get_passwords_parser(buffer, i);
    free(buffer);
    if(ans->error != NO_ERROR){
        printf("error\n");
    } else {
        printf("%zu entries:\n", ans->entry_qty);
        for(int i = 0; i<ans->entry_qty; i++){
            printf("\nEntry %d\n", i);
            printf("\tTime: %s\n",ans->entries[i].time);
            printf("\tUser: %s\n",ans->entries[i].user);
            printf("\tProtocol: %s\n",ans->entries[i].protocol);
            printf("\tDestination: %s\n",ans->entries[i].destination);
            printf("\tDestination port: %d\n",ans->entries[i].destination_port);
            printf("\tUsername: %s\n",ans->entries[i].username);
            printf("\tPassword: %s\n",ans->entries[i].password);
        }
    }
    free_passwords(ans);
    return 0;
}
*/
