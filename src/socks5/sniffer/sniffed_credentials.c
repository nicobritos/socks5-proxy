#include <stdlib.h>

#include "sniffed_credentials.h"

typedef struct sniffed_credentials_node_CDT {
    struct sniffed_credentials *credentials;
    sniffed_credentials_node next;
} sniffed_credentials_node_CDT;

typedef struct sniffed_credentials_CDT {
    sniffed_credentials_node first;
    sniffed_credentials_node last;
} sniffed_credentials_CDT;

sniffed_credentials_list sniffed_credentials_create_list() {
    return calloc(1, sizeof(sniffed_credentials_CDT));
}

void sniffed_credentials_add(sniffed_credentials_list list, struct sniffed_credentials *credentials) {
    if (list == NULL || credentials == NULL)
        return;

    sniffed_credentials_node node = malloc(sizeof(*node));
    if (node == NULL) return;

    node->credentials = credentials;
    node->next = NULL;
    if (list->last == NULL) {
        list->first = list->last = node;
    } else {
        list->last->next = node;
        list->last = node;
    }
}

sniffed_credentials_node sniffed_credentials_get_first(sniffed_credentials_list list) {
    return list != NULL ? list->first : NULL;
}

sniffed_credentials_node sniffed_credentials_get_next(sniffed_credentials_node node) {
    return node != NULL ? node->next : NULL;
}

struct sniffed_credentials *sniffed_credentials_get(sniffed_credentials_node node) {
    return node != NULL ? node->credentials : NULL;
}

void sniffed_credentials_destroy(sniffed_credentials_list list) {
    if (list == NULL) return;
    sniffed_credentials_node node = list->first;
    while (node != NULL) {
        sniffed_credentials_node aux = node->next;
        free(node);
        node = aux;
    }
}
