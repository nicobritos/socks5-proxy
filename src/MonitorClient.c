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
#include <errno.h>
#include <getopt.h>

#include "include/MonitorClient.h"

#define MAX_BUFFER 1024
#define MY_PORT_NUM 62324
#define HISTORICAL_CONNECTION 1
#define CONCURRENT_CONNECTIOS 2
#define BYTES_TRANSFERRED 3
#define PTC_UNSPEC 0
#define CONFIGURATION_MENU 1
#define METRIC_MENU 2
static int sd = -1, rc;
static char *address = "127.0.0.1";
static uint16_t port = 9090;
static struct addrinfo *res;
static bool logged = false;
static char buffer[MAX_BUFFER];
static char *username;
static char *password;


static bool authenticate_user(const char *username, const char *password);

static void login();

static void start_connection(int argc, char *argv[]);

static void check_command_line(int argc, char *argv[]);

static void get_address_information();

static void establish_connection();

static void get_metric(int metric);

static void get_menu_option();

static void get_metrics_menu();

static void finish_connection();

static uint16_t parse_port(const char *s);



/* TODO 
    -get_menu_option
    -finish_connection
*/
int main(int argc, char* argv[]){

    /* Initialize conection */
    start_connection(argc,argv);

    /* Already connected to the server */
    while(1){

        /* Request user to log in */
        if(!logged){
            login();
        } 
        else{
            /* show the menu options to the logged user */
            get_menu_option();
        }
    }

    /* Free resources */
    finish_connection();
}

/* TODO
    -definir datagrama
    -cargar el datagrama con usuario y password minimo
    -parsear respuesta para ver si valido el usuario o no
*/
static bool authenticate_user(const char *username, const char *password){
    
    /* Set datagram for request server authentication */
    const int DATGRAM_MAXLENGTH = (3 + 2*255);
    uint8_t datagram[DATGRAM_MAXLENGTH];
    uint8_t ver = 0x01;
    uint8_t ulen = (uint8_t)strlen(username);
    uint8_t plen = (uint8_t)strlen(password);
    int datalen = 3 + ulen + plen;

    /* Load version into datagram */
    datagram[0] = ver;

    /* Load ulen into datagram */
    datagram[1] = ulen;

    /* Load username into datagram */
    for(int i=0 ; i<ulen ; i++){
        datagram[2+i] = (uint8_t)username[i];
    }

    /* Load plen into datagram */
    datagram[2+ulen] = plen;

    /* Load password into datagram */
    for(int i=0 ; i<plen ; i++){
        datagram[3+ulen+i] = (uint8_t)password[i];
    }
     
    int ret;

    /* Send request to the server */
    ret = sctp_sendmsg (sd, (void *) datagram, (size_t) datalen,NULL, 0, 0, 0, 0, 0, 0);

    if(ret == -1){
        //ERROR
    }

    uint8_t answer[DATGRAM_MAXLENGTH];
    
    /* Receive the answer from the server */
    ret = sctp_recvmsg (sd, (void* ) answer, sizeof (buffer),(struct sockaddr *) NULL, 0,0,0);

    if(ret == -1){
        //ERROR
    }

    if(answer[1] == 0x00){
        return true;
    }

    return false;

    //PARSEAR LA RESPUESTA
}

static void login(){
    char username[MAX_BUFFER];
    char password[MAX_BUFFER];
    
    printf("Hello! To access the menu, first log in\n");

  do{
      printf("Username: ");
  } while(fgets(buffer, sizeof(buffer), stdin) == NULL);

    buffer[strcspn(buffer, "\r\n")] = 0;
    sscanf(buffer, "%s", username);

    if(strlen(username) > 255){
        printf("Username must be shorter");
        return;
    }

    int chances = 3;
    printf("Password: \n");
    while(chances > 0 && !logged){
        if(fgets(buffer, sizeof(buffer), stdin) != NULL){
            buffer[strcspn(buffer, "\r\n")] = 0;
            sscanf(buffer, "%s", password);
            if(strlen(password) <= 255)
                logged = authenticate_user(username,password);
            else
                printf("Password must be shorter");
            
        } else{
            printf("Password: \n");
            chances--;
        }
    }

    if(!logged){
        printf("Check if the username and password entered are correct\n");
        return;
    }
}

/* TODO
    -CREO hello al servidor
*/
static void start_connection(int argc, char *argv[]){

    /* Check if new config was sent via CL */
    check_command_line(argc,argv);

    /* Use setted config to get server info */
    get_address_information();
        
    /* Establish connection with server */
    establish_connection();

    //CREO QUE ESTA FALTANDO UN HELLO AL SERVIDOR
}

static uint16_t parse_port(const char *s) {
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

/* TODO
    -Ver si hay mas opciones por validar
*/
static void check_command_line(int argc, char *argv[]){
    //VALIDAR EL CASO DE EOF o ^D
    int optchar;
    while((optchar = getopt(argc, argv, ":L:P:")) != -1){
        switch(optchar){
            case 'L':
                address = malloc(strlen(optarg) + 1);
                memcpy(address, optarg, strlen(optarg) + 1);
                break;
            case 'P':
                port = parse_port(optarg);
                break;
            case ':':
                fprintf(stderr, "Missing argument after -%c\n",optopt);
                exit(EXIT_FAILURE);
            case '?':
                fprintf(stderr,"Unrecognized option -%c\n",optopt);
                exit(EXIT_FAILURE);
            default:
                //print_opt();
                exit(EXIT_FAILURE);
        }
    }
}

static void get_address_information(){
    
    /* This structure can be used to provide hints concerning the type of socket that the caller supports or wishes to use. */
    struct addrinfo hints = {
        .ai_flags = AI_PASSIVE,                /* Returned socket address structure is intended for use in a call to bind(2) */
        .ai_family = PF_UNSPEC,                /* Caller accept IPv4 or IPv6 */
        .ai_socktype = SOCK_STREAM,    
        .ai_protocol = PTC_UNSPEC,                /* Caller will accept any protocol */
        .ai_addr = NULL,
        .ai_canonname = NULL,
        .ai_next = NULL, 
    };

    
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
        fprintf(stderr, "Error establishing connection with the server via socket\n");
        exit(EXIT_FAILURE);
    }
}

/* TODO
    -Definir el dartagrama para enviar la solicitud
    -Parsear la respuesta para devolverle la metrica al usuario
*/
static void get_metric(int metric){
    //DEFINIR EL FORMATO DEL DATAGRAMA A ENVIAR
    uint8_t datagram[256];
    int datagramLength = 1;
    int ret;

    /* Send request to the server */
    ret = sctp_sendmsg (sd, (void *) datagram, (size_t) datagramLength,NULL, 0, 0, 0, 0, 0, 0);

    if(ret == -1){
        //ERROR
    }

    uint8_t answer[256];
    
    /* Receive the answer from the server */
    ret = sctp_recvmsg (sd, (void* ) answer, sizeof (buffer),(struct sockaddr *) NULL, 0,0,0);

    if(ret == -1){
        //ERROR
    }

    //PARSEAR LA RESPUESTA
}

/* TODO
    -definit get_configuration_menu
*/
static void get_menu_option(){
    printf("\nMenu options:\n");
    printf("[1] Configurations\n");
    printf("[2] Metrics\n");

    if(fgets(buffer,sizeof(buffer),stdin) == NULL){
        fprintf(stderr,"Please, choose an option.\n");
         return;
    }

    char *ptr;
    long ret;

    ret = strtoul(buffer,&ptr,10);

    switch(ret){
        case 1:
            // get_configuration_menu(CONFIGURATION_MENU);
            break;
        case 2:
            get_metrics_menu(METRIC_MENU);
            break;
        default:
            printf("Error: Invalid option: %lu \n Please try again with a valid option.",ret);
        break;
    }
}

static void get_metrics_menu(){
    printf("\nShow number of: \n");
    printf("[1] Historical connections\n");
    printf("[2] Concurrent connections\n");
    printf("[3] Bytes transferred\n");
    printf("[4] Back\n");

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
        case 4: 
            get_menu_option();
        default:
            printf("Error: Invalid option: %lu \n Please try again with a valid option.",ret);
        break;
    }
}

static void finish_connection(){
    free(address);
    free(username);
    free(password);
    free(res); //DUDANDO -> PORQUE HAY UN FREEADDRINFO()
}