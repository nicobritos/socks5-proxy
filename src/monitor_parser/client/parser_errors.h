#ifndef PARSER_ERRORS_H_
#define PARSER_ERRORS_H_

typedef enum errors{
    NO_ERROR,
    INVALID_INPUT_FORMAT_ERROR,  // Si el datagrama no cumple el formato del RFC
    REALLOC_ERROR,               // Si al hacer un realloc se produjo algun error
}parser_error_t;
#endif
