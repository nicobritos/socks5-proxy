#include "byte_formatter.h"

#define DEFINED_MULTIPLIERS 5
#define BYTE_MULTIPLIER 1024

/**
 * Calcula el multiplicador de bytes y setea el caracter correspondiente
 * Si el multiplicador es nulo, setea c en '\0'
 */
const char *byte_formatter_format(uint64_t bytes, double *d) {
    // Lo hacemos estatico porque no tiene sentido recrearlo en memoria
    static const char *multiplier[DEFINED_MULTIPLIERS] = {"B", "KB", "MB", "GB", "TB"};
    uint8_t i;
    *d = bytes;
    for (i = 0; i < DEFINED_MULTIPLIERS && bytes >= BYTE_MULTIPLIER; i++) {
        bytes /= BYTE_MULTIPLIER;
        *d /= BYTE_MULTIPLIER;
    }
    return multiplier[i];
}
