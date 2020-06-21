#ifndef PARSER_H_00180a6350a1fbe79f133adf0a96eb6685c242b6
#define PARSER_H_00180a6350a1fbe79f133adf0a96eb6685c242b6

/**
 * parser.c -- pequeÃ±o motor para parsers/lexers.
 *
 * El usuario describe estados y transiciones.
 * Las transiciones contienen una condiciÃ³n, un estado destino y acciones.
 *
 * El usuario provee al parser con bytes y Ã©ste retona eventos que pueden
 * servir para delimitar tokens o accionar directamente.
 */
#include <stdint.h>
#include <stddef.h>

/**
 * Evento que retorna el parser.
 * Cada tipo de evento tendrÃ¡ sus reglas en relaciÃ³n a data.
 */
struct parser_event {
    /** tipo de evento */
    unsigned type;
    /** caracteres asociados al evento */
    uint8_t  data[3];
    /** cantidad de datos en el buffer `data' */
    uint8_t  n;
    /** lista de eventos: si es diferente de null ocurrieron varios eventos */
    struct parser_event *next;
};

/** describe una transiciÃ³n entre estados  */
struct parser_state_transition {
    /* condiciÃ³n: un caracter o una clase de caracter. Por ej: '\r' */
    int       when;
    /** descriptor del estado destino cuando se cumple la condiciÃ³n */
    unsigned  dest;
    /** si no es NULL se ejecuta para determinar el .dest */
    unsigned  (*dest_f)(void *attachment, const uint8_t c);
    /** acciÃ³n 1 que se ejecuta cuando la condiciÃ³n es verdadera. requerida. */
    void    (*act1)(struct parser_event *ret, const uint8_t c);
    /** otra acciÃ³n opcional */
    void    (*act2)(struct parser_event *ret, const uint8_t c);
};

/** predicado para utilizar en `when' que retorna siempre true */
static const int ANY = 1u << 9u;

/** declaraciÃ³n completa de una mÃ¡quina de estados */
struct parser_definition {
    /** cantidad de estados */
    const unsigned                         states_count;
    /** por cada estado, sus transiciones */
    const struct parser_state_transition **states;
    /** cantidad de estados por transiciÃ³n */
    const size_t                          *states_n;

    /** estado inicial */
    const unsigned                         start_state;
};

/**
 * inicializa el parser.
 *
 * `classes`: caracterizaciÃ³n de cada caracter (256 elementos)
 */
struct parser *
parser_init    (const unsigned *classes,
                const struct parser_definition *def);

void
parser_set_attachment(struct parser *p, void *attachment);

/** destruye el parser */
void
parser_destroy  (struct parser *p);

/** permite resetear el parser al estado inicial */
void
parser_reset    (struct parser *p);

/**
 * el usuario alimenta el parser con un caracter, y el parser retorna un evento
 * de parsing. Los eventos son reusado entre llamadas por lo que si se desea
 * capturar los datos se debe clonar.
 */
const struct parser_event *
parser_feed     (struct parser *p, const uint8_t c);

/**
 * En caso de la aplicacion no necesite clases caracteres, se
 * provee dicho arreglo para ser usando en `parser_init'
 */
const unsigned *
parser_no_classes(void);


#endif
