#ifndef PC_2020A_6_TPE_SOCKSV5_LOG_HELPER_H
#define PC_2020A_6_TPE_SOCKSV5_LOG_HELPER_H

#define LOG_LEVEL log_severity_debug

enum log_severity {
    log_severity_debug,
    log_severity_info,
    log_severity_warning,
    log_severity_error
};

typedef struct log_CDT *log_t;

/**
 * Inicializa el log del sistema.
 * Devuelve el log creado
 * @param filename
 * @param severity
 */
log_t init_system_log(const char *filename, enum log_severity severity);

/**
 * Inicializa un log especifico.
 * Devuelve el log creado
 * @param filename
 * @param severity
 */
log_t init_log(const char *filename, enum log_severity severity);

/**
 * Appendea un string a un log con un severity determinado
 * Solo lo hace si el severity del log esta seteado en un
 * nivel igual o inferior (mas verbose) que el pasado.
 * Formatea el string con fprintf
 * @param log
 * @param severity
 * @param s
 * @param argc la cantidad de argumentos
 */
void append_to_log(log_t log, enum log_severity severity, const char *s, int argc, ...);

/**
 * Cierra un log especifico.
 * @param log
 */
void close_log(log_t log);

/**
 * Cierra el log del sistema.
 * @param log
 */
void close_system_log();

#endif //PC_2020A_6_TPE_SOCKSV5_LOG_HELPER_H
