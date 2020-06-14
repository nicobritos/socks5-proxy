#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <stdarg.h>
#include <semaphore.h>
#include <string.h>

#include "log_helper.h"

#define MAX_LOG_COUNT 500

#define DEBUG_STR "DEBUG"
#define INFO_STR "INFO"
#define WARNING_STR "WARNING"
#define ERROR_STR "ERROR"

typedef struct log_node_CDT *log_node_t;

typedef struct log_CDT {
    FILE *file;
    char *filename;
    enum log_severity severity;
    log_node_t first;
    log_node_t last;
    uint64_t count;

    pthread_t thread;
    sem_t semaphore;
    pthread_mutex_t mutex;
    bool done;
} log_CDT;

typedef struct log_node_CDT {
    char *s;
    log_node_t next;
} log_node_CDT;

static log_t system_log;


/** ------------- DECLARATIONS ------------- */
/**
 * Returns true if the string should be added
 * @param log
 */
static bool should_append_(log_t log, enum log_severity severity);

/**
 * Idem funcion append_to_log pero sin chequeo
 * @param log
 * @param s
 */
static void append_to_log_s(log_t log, char *s);

/**
 * Esta es la funcion loop de cada thread. Estan manejadas por un semaforo de cada log
 * @return NULL
 */
static void *thread_loop_(void *l);

/**
 * Remueve el primer elemento de la cola usando el mutex
 * @param log
 */
static void remove_first_(log_t log);

/**
 * Devuelve la representacion en str de un severity
 * @param severity
 */
static const char *get_severity_str_(enum log_severity severity);

/** ------------- DEFINITIONS ------------- */
/** ------------- PUBLIC ------------- */
/**
 * Inicializa el log del sistema.
 * Devuelve el log creado
 * @param filename
 * @param severity
 */
log_t init_system_log(const char *filename, enum log_severity severity) {
    if (system_log != NULL) return system_log;
    return system_log = init_log(filename, severity);
}

/**
 * Inicializa un log especifico.
 * Si no se puede inicializar por algun problema devuelve false, sino true
 * @param filename
 * @param severity
 */
log_t init_log(const char *filename, enum log_severity severity) {
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

    if (sem_init(&log->semaphore, 0, 0) != 0) {
        free(log->filename);
        fclose(log->file);
        free(log);
        return NULL;
    }
    if (pthread_mutex_init(&log->mutex, NULL) != 0) {
        free(log->filename);
        fclose(log->file);
        sem_destroy(&log->semaphore);
        free(log);
        return NULL;
    }
    if (pthread_create(&log->thread, NULL, thread_loop_, log) != 0) {
        free(log->filename);
        fclose(log->file);
        pthread_mutex_destroy(&log->mutex);
        sem_destroy(&log->semaphore);
        free(log);
        return NULL;
    }
    return log;
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
void append_to_log(log_t log, enum log_severity severity, const char *s, int argc, ...) {
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
    time_t timer;
    char buffer[26];
    struct tm* tm_info;
    timer = time(NULL);
    tm_info = localtime(&timer);
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    /** Calculamos el espacio que necesitamos para el string final */
    n = snprintf(NULL, 0, "[%s] [%s] %s\n", buffer, get_severity_str_(severity), out);
    char *out2 = malloc(sizeof(*out2) * (n + 1));
    if (out2 == NULL) {
        free(out);
        return;
    }
    sprintf(out2, "[%s] [%s] %s\n", buffer, get_severity_str_(severity), out);
    free(out); // No lo vamos a usar

    append_to_log_s(log, out2);
}

/**
 * Cierra un log especifico.
 * @param log
 */
void close_log(log_t log) {
    if (log->done) return;

    log->done = true;

    sem_post(&log->semaphore);
    /** Esperamos a que se escriba todo lo que hay para escribir */
    pthread_join(log->thread, NULL);

    log_node_t aux, node = log->first;
    while (node != NULL) {
        aux = node->next;
        free(node->s);
        free(node);
        node = aux;
    }

    free(log->filename);
    fclose(log->file);
    pthread_mutex_destroy(&log->mutex);
    sem_destroy(&log->semaphore);
    free(log);
}

/**
 * Cierra el log del sistema.
 * @param log
 */
void close_system_log() {
    if (system_log == NULL) return;
    close_log(system_log);
    system_log = NULL;
}

/** ------------- PRIVATE ------------- */
/**
 * Returns true if the string should be added
 * @param log
 */
static bool should_append_(log_t log, enum log_severity severity) {
    if (log->severity > severity) return false;
    if (log->count >= MAX_LOG_COUNT) {
        if (log != system_log && system_log->severity >= log_severity_warning) {
            append_to_log(
                    system_log,
                    log_severity_warning,
                    "Could not append to log with filename: '%s' reason: Queue maxed out",
                    1,
                    log->filename
            );
        }

        return false;
    }
    return true;
}

/**
 * Idem funcion append_to_log pero sin chequeo y pasa el string final
 * @param log
 * @param log_severity
 * @param s
 */
static void append_to_log_s(log_t log, char *s) {
    log_node_t node = malloc(sizeof(*node));
    if (node == NULL) return;
    node->next = NULL;
    node->s = s;

    pthread_mutex_lock(&log->mutex);

    if (log->last != NULL) log->last->next = node;
    if (log->first == NULL) log->first = node;
    log->count++;
    sem_post(&log->semaphore);

    pthread_mutex_unlock(&log->mutex);
}

/**
 * Esta es la funcion loop de cada thread. Estan manejadas por un semaforo de cada log
 */
static void *thread_loop_(void *l) {
    log_t log = (log_t) l;
    while (!log->done) {
        sem_wait(&log->semaphore);

        while (log->count > 0) {
            fputs(log->first->s, log->file);
            fflush(log->file);

            pthread_mutex_lock(&log->mutex);
            remove_first_(log);
            pthread_mutex_unlock(&log->mutex);
        }
    }

    return NULL;
}

/**
 * Remueve el primer elemento de la cola
 * @param log
 */
static void remove_first_(log_t log) {
    if (log->first != NULL) {
        free(log->first->s);
        log_node_t aux = log->first;
        log->first = log->first->next;
        if (log->last == aux) {
            log->last = NULL;
        }
        free(aux);
        log->count--;
    }
}

/**
 * Devuelve la representacion en str de un severity
 * @param severity
 */
static const char *get_severity_str_(const enum log_severity severity) {
    switch (severity) {
        case log_severity_warning:
            return WARNING_STR;
        case log_severity_debug:
            return DEBUG_STR;
        case log_severity_error:
            return ERROR_STR;
        case log_severity_info:
            return INFO_STR;
        default:
            return "";
    }
}
