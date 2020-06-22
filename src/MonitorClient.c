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
#include "monitor_parser/client/auth_server_response_parser.h"

#include "MonitorClient.h"

#define MAX_BUFFER 1024
#define MY_PORT_NUM 57610
#define HISTORICAL_CONNECTION 1
#define CONCURRENT_CONNECTIOS 2
#define BYTES_TRANSFERRED 3
#define PTC_UNSPEC 0
#define CONFIGURATION_MENU 1
#define METRIC_MENU 2
static int sd = -1, rc;
static char *address = "127.0.0.1";
static uint16_t port = 57610;
static struct addrinfo *res;
static bool logged = false;
static char buffer[MAX_BUFFER];
static char *username;
static char *password;
struct sctp_sndrcvinfo sndrcvinfo;
int flags;



static bool authenticate_user(const char *username, const char *password);

static void login();

static void start_connection(int argc, char *argv[]);

static void check_command_line(int argc, char *argv[]);

static void get_address_information();

static void establish_connection();

static void get_metrics();

static void get_menu_option();

static void finish_connection();

static uint16_t parse_port(const char *s);


int main(int argc, char* argv[]){

    start_connection(argc,argv);

    while(1){
        if(!logged){
            login();
        } 
        else{
            get_menu_option();
        }
    }
    finish_connection();
}


static void requestToServer(const uint8_t *request, const uint8_t reqlen, uint8_t *response, const uint8_t reslen, bool *reqflag, bool *resflag){
    int ret;
    ret = sctp_sendmsg (sd, (void *)request, (size_t) reqlen,NULL, 0, 0, 0, 0, 0, 0);

    if(ret == -1 || ret == 0){
        *reqflag = false;
        return;
    } 
    ret = sctp_recvmsg (sd, response, 10,(struct sockaddr *) NULL, 0,&sndrcvinfo, &flags);
    if(ret == -1 || ret == 0){
        *resflag = false;
        return;
    }
}

static bool authenticate_user(const char *username, const char *password){

    /* REQUEST
    +-----+----------+----------+
    | VER |  UNAME   |  PASSWD  |
    +-----+----------+----------+
    |  1  | Variable | Variable |
    +-----+----------+----------+
    */

    const int DATAGRAM_MAX_LENGTH = (1 + 2*255);
    uint8_t datagram[DATAGRAM_MAX_LENGTH];

    const uint8_t ver = 0x01;
    const uint8_t ulen = (uint8_t) strlen(username);
    const uint8_t plen = (uint8_t) strlen(password);
    const uint8_t datalen = 3 + ulen + plen;

    datagram[0] = ver;
    strcpy(datagram+1,username);
    strcpy(datagram+(1+ulen+1),password);

    const int ANSWER_MAX_LENGTH = (25);
    uint8_t answer[ANSWER_MAX_LENGTH];

    bool *dflag = true;
    bool *aflag = true;

    requestToServer(datagram,datalen,answer,sizeof(uint8_t) * ANSWER_MAX_LENGTH,&dflag,&aflag);

    if(!dflag){
        printf("Error sending authentication request\n");

    }

    if(!aflag){
        printf("Error receiving authentication response\n");
    }


    /* RESPONSE
    +--------+----------+
    | STATUS |  MESSAGE |
    +--------+----------+
    |   0    | Variable |
    +--------+----------+
    */

    struct auth_response * ans = auth_response_parser(answer, strlen(answer)+1);
    if(ans->error != 0){
        printf("error\n");
    } else {
        printf("%s\n", ans->message);
        if(ans->status == 0x01){
            return true;
        }
    }
    return false;
}


static void login(){
    char username[MAX_BUFFER];
    char password[MAX_BUFFER];
    
    printf("\nHello! To access the menu, first log in\n");
  
    printf("Username: ");
    if(fgets(buffer, sizeof(buffer), stdin) != NULL){
        buffer[strcspn(buffer, "\r\n")] = '\0';
        sscanf(buffer, "%s", username);
    }

    if(strlen(username) > 255){
        printf("Username must be shorter");
        return;
    }
    
    printf("Password: ");
    if(fgets(buffer, sizeof(buffer), stdin) != NULL){
        buffer[strcspn(buffer, "\r\n")] = '\0';
        sscanf(buffer, "%s", password);
        if(strlen(password) <= 255)
            logged = authenticate_user(username,password);
        else
            printf("Password must be shorter");
    }

    if(!logged){
        printf("Check if the username and password are correct\n");
        return;
    }
}

static void start_connection(int argc, char *argv[]){

    check_command_line(argc,argv);

    get_address_information();
        
    establish_connection();
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
    int oc;
    while((oc = getopt(argc, argv, ":L:P:")) != -1){
        switch(oc){
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
                exit(EXIT_FAILURE);
        }
    }
}

static void get_address_information(){
    
    struct addrinfo hints = {
        .ai_flags = AI_PASSIVE,                /* Returned socket address structure is intended for use in a call to bind(2) */
        .ai_family = PF_UNSPEC,                /* Caller accept IPv4 or IPv6 */
        .ai_socktype = SOCK_STREAM,    
        .ai_protocol = PTC_UNSPEC,             /* Caller will accept any protocol */
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
}

static void establish_connection(){
    
    sd = socket(res->ai_family, res->ai_socktype, IPPROTO_SCTP);
    if(sd == -1){
        fprintf(stderr,"Error creating socket with the server using %s:%hu\n",address,port);
        exit(EXIT_FAILURE);
    }

    rc = connect(sd, res->ai_addr, res->ai_addrlen);
    if(rc == -1){
        fprintf(stderr, "Error establishing connection with the server via socket\n");
        exit(EXIT_FAILURE);
    }
}

static void get_metrics(){

    /* REQUEST
    +--------+
    |  CODE  |
    +--------+
    |   1    |
    +--------+
    */

    const int DATAGRAM_MAX_LENGTH = 1;
    uint8_t datagram[DATAGRAM_MAX_LENGTH];
    datagram[0] = 0x01;

    const int ANSWER_MAX_LENGTH = 12;
    uint8_t answer[ANSWER_MAX_LENGTH];

    bool *dflag = true;
    bool *aflag = true;

    requestToServer(datagram, sizeof(uint8_t) * DATAGRAM_MAX_LENGTH, answer, sizeof(uint8_t) * ANSWER_MAX_LENGTH, &dflag, &aflag);

    /* RESPONSE
    +----------+----------+----------+
    |   ECON   |   ACON   |  BYTES   | 
    +----------+----------+----------+
    |  	4	   |     4    |     4    |  
    +----------+----------+----------+
    */

   if(!dflag){
       printf("Error sending metrics request\n");
   }

   if(!aflag){
       printf("Error receiving metrics response\n");
   }

    struct metrics * ans = get_metrics_parser(answer, strlen(answer)+1);
    if(ans->error != NO_ERROR){
        printf("error\n");
    } else {
        printf("%u\n", ans->established_cons);
        printf("%u\n", ans->actual_cons);
        printf("%u\n", ans->bytes_transferred);
    }
}

static void get_users(){

    /* REQUEST
    +--------+
    |  CODE  |
    +--------+
    |   1    |
    +--------+
    */

    const int DATAGRAM_MAX_LENGTH = 1;
    uint8_t datagram[DATAGRAM_MAX_LENGTH];
    datagram[0] = 0x02;

    const int ANSWER_MAX_LENGTH = 255;
    uint8_t answer[ANSWER_MAX_LENGTH];

    bool *dflag = true;
    bool *aflag = true;

    requestToServer(datagram, sizeof(uint8_t) * DATAGRAM_MAX_LENGTH, answer, sizeof(uint8_t) * ANSWER_MAX_LENGTH, &dflag, &aflag);

    /* RESPONSE
    +------------+------------+
    |    USER    |   STATUS   | 
    +------------+------------+
    |  Variable  |     1      |  
    +------------+------------+
    */

    struct users * ans = get_users_parser(buffer, i);
    if(ans->error != NO_ERROR){
        printf("error\n");
    } else {
        printf("Users quantity: %zu\n", ans->users_qty);
        for(int i = 0; i<ans->users_qty; i++){
            printf("User: %s\tStatus: %d\n", ans->users[i].user, ans->users[i].status);
        }
    }


}

static void get_menu_option(){
    printf("\nMenu options:\n");
    printf("[1] Show metrics\n");
    printf("[2] Show users\n");
    printf("[3] Show access logs\n");
    printf("[4] Show passwords\n");
    printf("[5] Show vars\n");


    if(fgets(buffer,sizeof(buffer),stdin) == NULL){
        fprintf(stderr,"Please, choose an option.\n");
         return;
    }

    char *ptr;
    long ret;

    ret = strtoul(buffer,&ptr,10);

    switch(ret){
        case 1:
            get_metrics();
            break;
        case 2:
            get_users();
            break;
        case 3:
            //get_access_log();
            break;
        case 4:
            //get_passwords();
            break;
        case 5:
            //get_vars();
            break;
        
        default:
            printf("Error: Invalid option: %lu \n Please try again with a valid option.",ret);
        break;
    }
}

static void finish_connection(){
    free(address);
    free(username);
    free(password);
}