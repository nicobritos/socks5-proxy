#ifndef PC_2020A_6_TPE_SOCKSV5_LOG_HELPER_H
#define PC_2020A_6_TPE_SOCKSV5_LOG_HELPER_H

#define DEFAULT_LOG_LEVEL log_severity_debug

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
log_t logger_init_system_log(const char *filename, enum log_severity severity);

/**
 * Inicializa un log especifico.
 * Devuelve el log creado
 * @param filename
 * @param severity
 */
log_t logger_init_log(const char *filename, enum log_severity severity);

/**
 * Devuelve el log del sistema si esta inicializado, NULL sino
 * @param filename
 * @param severity
 */
log_t logger_get_system_log();

/**
 * Setea un nuevo severity para el logger
 * @param log
 * @param severity
 */
void logger_set_log_severity(log_t log, enum log_severity severity);

/**
 * Devuelve un string que representa el severity, NULL si es invalido
 * @param severity
 * @return
 */
const char *logger_get_log_severity_str(enum log_severity severity);

/**
 * Devuelve el severity de un log
 */
enum log_severity logger_get_log_severity(log_t log);

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
void logger_append_to_log(log_t log, enum log_severity severity, const char *s, int argc, ...);

/**
 * Cierra un log especifico.
 * @param log
 */
void logger_close_log(log_t log);

/**
 * Cierra el log del sistema.
 * @param log
 */
void logger_close_system_log();

/**
 * Retorna la representacion del current datetime
 * en un string con formato ISO 8601. El mismo debe
 * luego ser liberado
 */
char *logger_get_datetime();

#endif //PC_2020A_6_TPE_SOCKSV5_LOG_HELPER_H
