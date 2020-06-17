//
// Created by Nacho Grasso on 07/06/2020.
//

/* ----- INCLUDES ----- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <limits.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>

#include "include/MonitorClient.h"

#define MAX_BUFFER 1024
#define MY_PORT_NUM 62324
#define HISTORICAL_CONNECTION 1
#define CONCURRENT_CONNECTIOS 2
#define BYTES_TRANSFERRED 3
#define PTC_UNSPEC 0

static int sd = -1, rc;
static char *address = "127.0.0.1";
static uint16_t port = 9090;
static struct addrinfo hints, *res;
static bool logged = false;




int main(int argc, char* argv[]){

    /* Initialize conection */
    start_connection(argc,argv);

    /* Already connected to the server */
    while(1){

        /* Request user to log in */
        if(!logged)
            login();

        /* show the menu options to the logged user */
        print_menu();

        /* execute if valid the option chosen by user */
        get_menu_option();
    }

    /* Free resources */
    finish_connection();
}

static void login(){
    char username[MAX_BUFFER];
    char password[MAX_BUFFER];
    printf("Hello! To access the menu, first log in\n");
    while(fgets(buffer,sizeof(buffer),stdin) == NULL){
        printf("Username: ")
        
    }



}


static void start_connection(int argc, char *argv[]){

    /* Check if new config was sent via CL */
    check_command_line(argc,argv);

    /* Use setted config to get server info */
    get_address_information();
        
    /* Establish connection with server */
    establish_connection();

    //Creo que me esta faltando un HELLO al SERVER
}

static uint16_t port(const char *s) {
     char *end     = 0;
     const long sl = strtol(s, &end, 10);

     if (end == s|| '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 0 || sl > USHRT_MAX) {
         fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
         exit(EXIT_FAILURE);
         return EXIT_FAILURE;
     }
     return (uint16_t)sl;
}

static void check_command_line(int argc, char *argv[]){
    //validar caso de pasarle EOF
    int optchar;
    while((c = getopt(argc, argv, ":L:P:")) != -1){
        switch(optchar){
            case 'L':
                size_t optarg_size = strlen(optarg) + 1;
                address = malloc(optarg_size);
                memcpy(address, optarg, optarg_size);
                break;
            case 'P':
                port = port(optarg);
                break;
            case ':':
                fprintf(stderr, "Missing argument after -%c\n",optopt);
                exit(EXIT_FAILURE);
            case '?':
                fprintf(stderr,"Unrecognized option -%c\n",optopt);
                exit(EXIT_FAILURE);
            default:
                print_opt();
                exit(EXIT_FAILURE);
        }
    }
}

static void get_address_information(){
    
    /* This structure can be used to provide hints concerning the type of socket that the caller supports or wishes to use. */

    hints.ai_flags = AI_PASSIVE;                /* Returned socket address structure is intended for use in a call to bind(2) */
    hints.ai_family = PF_UNSPEC;                /* Caller accept IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;    
    hints.protocol = PTC_UNSPEC;                /* Caller will accept any protocol */
    hints.ai_addrlen = NULL;
    hints.ai_addr = NULL;
    hints.ai_canonname = NULL;
    hints.ai_next = NULL; 
    

    char port_str[15];
    snprintf(port_str, sizeof(port_str), "%hu", port);

    /********************************************************************/
    /* Get the address information for the server using getaddrinfo().  */
    /********************************************************************/

    int gai = getaddrinfo(address, port_str, &hints, &res);
    if(gai != 0){
        fprintf("Host not found: %s\n", gai_strerror(rc));
        exit(EXIT_FAILURE);
    }

    /* res has now server valid information */
}

static void establish_connection(){
    
    /* Creat socket to the server */
    sd = socket(res->ai_family, res->ai_socktype, IPPROTO_SCTP);
    if(sd == -1){
        fprintf(stderr,"Error creating socket with the server using %s:%hu\n",address,port);
        exit(EXIT_FAILURE);
    }

    /* Establish connection through the socket */
    rc = connect(sd, res->ai_addr, res->ai_addrlen);
    if(rc == -1){
        fprintf(stderr, "Error establishing connection with the server via socket");
        exit(EXIT_FAILURE);
    }
}

static void get_metrics(){
    printf("Show number of: \n")
    printf("[1] Historical connections\n");
    printf("[2] Concurrent connections\n");
    print("[3] Bytes transferred\n");

    if(fgets(buffer, sizeof(buffer), stdin) == NULL){
         fprintf(stderr,"Please, choose an option.\n");
         return;
    } 

    char *ptr;
    long ret;

    ret = strtoul(buffer,&ptr,10);

    switch(ret){
        case 1:
            get_metric(HISTORICAL_CONNECTION);
            break;
        case 2:
            get_metric(CONCURRENT_CONNECTIOS);
            break;
        case 3:
            get_metric(BYTES_TRANSFERRED);
            break;
        default:
            printf("Error: Invalid option: %lu \n Please try again with a valid option.",ret);
        break;
    }
}

static void get_metric(int metric){
    //definir el formato del datagrama a enviar y largo
    uint8_t datagram[256]
    int datagramLength = 1;
    int ret;

    //mando solicitud
    ret = sctp_sendmsg (connSock, (void *) datagram, (size_t) datagramLength,NULL, 0, 0, 0, 0, 0, 0);

    if(ret == -1){
        //ocurrio error
    }

    uint8_t answer[256];
    //recibo lo solicitado
    ret = sctp_recvmsg (connSock, (void* ) answer, sizeof (buffer),(struct sockaddr *) NULL, 0,0,0);

    if(ret == -1){
        //ocurrio error
    }

    //parsear respuesta


}