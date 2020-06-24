/**
 * Los logs antes corrian en un thread aparte (un thread por log)
 * para evitar bloquear si se estan escribiendo muchos logs.
 * Pero se requiere que el server sea monolitico.
 * No hay otra forma de implementar un non-blocking write a un file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

#include "log_helper.h"

#define DEBUG_STR "DEBUG"
#define INFO_STR "INFO"
#define WARNING_STR "WARNING"
#define ERROR_STR "ERROR"

typedef struct log_CDT {
    FILE *file;
    char *filename;
    enum log_severity severity;
} log_CDT;

static log_t system_log;


/** ------------- DECLARATIONS ------------- */
/**
 * Returns true if the string should be added
 * @param log
 */
static bool should_append_(log_t log, enum log_severity severity);

/**
 * Idem funcion logger_append_to_log pero sin chequeo
 * @param log
 * @param s
 */
static void append_to_log_s(log_t log, char *s);

/** ------------- DEFINITIONS ------------- */
/** ------------- PUBLIC ------------- */
/**
 * Inicializa el log del sistema.
 * Devuelve el log creado
 * @param filename
 * @param severity
 */
log_t logger_init_system_log(const char *filename, enum log_severity severity) {
    if (system_log != NULL) return system_log;
    return system_log = logger_init_log(filename, severity);
}

/**
 * Inicializa un log especifico.
 * Si no se puede inicializar por algun problema devuelve false, sino true
 * @param filename
 * @param severity
 */
log_t logger_init_log(const char *filename, enum log_severity severity) {
    log_t log = calloc(sizeof(*log), 1);
    if (log == NULL) return NULL;

    uint64_t len = strlen(filename);
    log->filename = malloc(sizeof(*log->filename) * (len + 1));
    if (log->filename == NULL) return NULL;
    memcpy(log->filename, filename, len + 1); // Copia tambien el NULL

    log->file = fopen(filename, "a");
    if (log->file == NULL) {
        free(log->filename);
    }

    log->severity = severity;
    return log;
}

/**
 * Devuelve el log del sistema si esta inicializado, NULL sino
 * @param filename
 * @param severity
 */
log_t logger_get_system_log() {
    return system_log;
}

/**
 * Setea un nuevo severity para el logger
 * @param log
 * @param severity
 */
void logger_set_log_severity(log_t log, enum log_severity severity) {
    if (log == NULL) return;
    log->severity = severity;
}

/**
 * Devuelve un string que representa el severity, NULL si es invalido
 * @param severity
 * @return
 */
const char *logger_get_log_severity_str(enum log_severity severity) {
    switch (severity) {
        case log_severity_info: return INFO_STR;
        case log_severity_debug: return DEBUG_STR;
        case log_severity_error: return ERROR_STR;
        case log_severity_warning: return WARNING_STR;
        default: return NULL;
    }
}

/**
 * Devuelve el severity de un log
 */
enum log_severity logger_get_log_severity(log_t log) {
    if (log == NULL)
        return log_severity_error; // Arbitrary
    return log->severity;
}

/**
 * Appendea un string a un log con un severity determinado
 * Solo lo hace si el severity del log esta seteado en un
 * nivel igual o inferior (mas verbose) que el pasado
 * Formatea el string con fprintf
 * @param log
 * @param log_severity
 * @param s
 */
void logger_append_to_log(log_t log, enum log_severity severity, const char *s, int argc, ...) {
    if (!should_append_(log, severity)) return;

    va_list args;

    /** Calculamos el espacio que necesitamos para el string pasado */
    va_start(args, argc);
    int64_t n = vsnprintf(NULL, 0, s, args);
    va_end(args);
    char *out = malloc(sizeof(*out) * (n + 1));
    if (out == NULL) return;
    va_start(args, argc);
    vsprintf(out, s, args);
    va_end(args);

    /** Formateamos el string final con el datetime y el severity */
    char *datetime = logger_get_datetime();
    if (datetime == NULL) {
        free(out);
        return;
    }

    /** Calculamos el espacio que necesitamos para el string final */
    n = snprintf(NULL, 0, "[%s] [%s] %s\n", datetime, logger_get_log_severity_str(severity), out);
    char *out2 = malloc(sizeof(*out2) * (n + 1));
    if (out2 == NULL) {
        free(datetime);
        free(out);
        return;
    }
    sprintf(out2, "[%s] [%s] %s\n", datetime, logger_get_log_severity_str(severity), out);
    free(out); // No lo vamos a usar
    free(datetime);

    append_to_log_s(log, out2);

    free(out2);
}

/**
 * Cierra un log especifico.
 * @param log
 */
void logger_close_log(log_t log) {
    if (log == NULL) return;
    free(log->filename);
    fclose(log->file);
    free(log);
}

/**
 * Cierra el log del sistema.
 * @param log
 */
void logger_close_system_log() {
    if (system_log == NULL) return;
    logger_close_log(system_log);
    system_log = NULL;
}

/**
 * Retorna la representacion del current datetime
 * en un string con formato ISO 8601. El mismo debe
 * luego ser liberado
 */
char *logger_get_datetime() {
    time_t timer;
    char *r = calloc(26, sizeof(*r));
    if (r == NULL) return NULL;

    struct tm* tm_info;
    timer = time(NULL);
    tm_info = localtime(&timer);
    strftime(r, 26, "%Y-%m-%dT%H:%M:%S%z", tm_info);

    return r;
}

/** ------------- PRIVATE ------------- */
/**
 * Returns true if the string should be added
 * @param log
 */
static bool should_append_(log_t log, enum log_severity severity) {
    if (log->severity > severity) return false;
    return true;
}

/**
 * Idem funcion logger_append_to_log pero sin chequeo y pasa el string final
 * @param log
 * @param log_severity
 * @param s
 */
static void append_to_log_s(log_t log, char *s) {
    fputs(s, log->file);
    fflush(log->file);

//    FILE *console = log == system_log ? stderr : stdout;
//    fputs(s, console);
//    fflush(console);
}
