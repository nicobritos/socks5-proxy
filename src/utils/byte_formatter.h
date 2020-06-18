#ifndef PC_2020A_6_TPE_SOCKSV5_BYTE_FORMATTER_H
#define PC_2020A_6_TPE_SOCKSV5_BYTE_FORMATTER_H

#include <stdint.h>

/**
 * Calcula el multiplicador de bytes y devuelve el multiplicador correspondiente
 * Setea en d
 */
const char *byte_formatter_format(uint64_t bytes, double *d);

#endif //PC_2020A_6_TPE_SOCKSV5_BYTE_FORMATTER_H
