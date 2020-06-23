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
#include "monitor_parser/client/get_metrics_parser.h"
#include "monitor_parser/client/get_access_log_parser.h"
#include "monitor_parser/client/get_users_parser.h"
#include "monitor_parser/client/get_vars_parser.h"
#include "monitor_parser/client/get_passwords_parser.h"

#include "MonitorClient.h"

#define MAX_BUFFER 1024
#define MY_PORT_NUM 57614
#define HISTORICAL_CONNECTION 1
#define CONCURRENT_CONNECTIOS 2
#define BYTES_TRANSFERRED 3
#define PTC_UNSPEC 0
#define CONFIGURATION_MENU 1
#define METRIC_MENU 2
static int sd = -1, rc;
static char *address = "127.0.0.1";
static uint16_t port = 57614;
static struct addrinfo *res;
static bool logged = true;
static char buffer[MAX_BUFFER];
static char *username;
static char *password;
struct sctp_sndrcvinfo sndrcvinfo;
int flags;



static bool authenticate_user(const char *username, const char *password);

static void login();

static void start_connection(int argc, char *argv[]);

static void get_address_information();

static void establish_connection();

static void get_metrics();

static void get_menu_option();

static void finish_connection();

static void get_metrics(uint8_t *request,int length);

static void get_users(uint8_t *request,int length);

static void get_access_log(uint8_t *request,int length);

static void get_passwords(uint8_t *request,int length);

static void get_vars(uint8_t *request,int length);



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


static int requestToServer(const uint8_t *request, const uint8_t reqlen, uint8_t *response, const uint8_t reslen){
    int ret;
    ret = sctp_sendmsg (sd, (void *)request, (size_t) reqlen,NULL, 0, 0, 0, 0, 0, 0);

    if(ret == -1 || ret == 0){
        return -1;
    } 
    ret = sctp_recvmsg (sd, response, reslen,(struct sockaddr *) NULL, 0,&sndrcvinfo, &flags);
    if(ret == -1 || ret == 0){
        return -1;
    }
    return ret;
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
    strcpy((char *)datagram+1,username);
    strcpy((char *)datagram+(1+ulen+1),password);

    const int ANSWER_MAX_LENGTH = 255;
    uint8_t answer[ANSWER_MAX_LENGTH];

    int ret = requestToServer(datagram,datalen,answer,sizeof(uint8_t) * ANSWER_MAX_LENGTH);

    if(ret == -1){
        printf("Error sending request or receiving response\n");
    }


    /* RESPONSE
    +--------+----------+
    | STATUS |  MESSAGE |
    +--------+----------+
    |   0    | Variable |
    +--------+----------+
    */

    struct auth_response * ans = auth_response_parser(answer, ret);
    if(ans->error != 0){
        printf("Error\n");
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
}

static void start_connection(int argc, char *argv[]){

    get_address_information();
        
    establish_connection();
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
        printf("Host not found: %s\n", gai_strerror(rc));
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

static void get_command(const int code){

    /* REQUEST
    +--------+
    |  CODE  |
    +--------+
    |   1    |
    +--------+
    */

    const int DATAGRAM_MAX_LENGTH = 1;
    uint8_t datagram[DATAGRAM_MAX_LENGTH];
    datagram[0] = code;

    const int ANSWER_MAX_LENGTH = 255;
    uint8_t answer[ANSWER_MAX_LENGTH];

    int ret = requestToServer(datagram, sizeof(uint8_t) * DATAGRAM_MAX_LENGTH, answer, sizeof(uint8_t) * ANSWER_MAX_LENGTH);

    if(ret == -1){
        printf("Error sending request or receiving response\n");
    }

    switch (code){
        case 0x01:
            get_metrics(answer,ret);
            break;
        case 0x02:
            get_users(answer,ret);
            break;
        case 0x03:
            get_access_log(answer,ret);
            break;
        case 0x04:
            get_passwords(answer,ret);
            break;
        case 0x05:
            get_vars(answer,ret);
        default:
            break;
    }


}

static void get_metrics(uint8_t *response, int length){

    /* RESPONSE
    +----------+----------+----------+
    |   ECON   |   ACON   |  BYTES   | 
    +----------+----------+----------+
    |  	4	   |     4    |     4    |  
    +----------+----------+----------+
    */

    // struct metrics * ans = get_metrics_parser(response, length);
    // if(ans->error != NO_ERROR){
    //     printf("error\n");
    // } else {
    //     printf("%lu\n", ans->established_cons);
    //     printf("%lu\n", ans->actual_cons);
    //     printf("%lu\n", ans->bytes_transferred);
    // }
    // free_metrics(ans);
}

static void get_users(uint8_t *response, int length){

    /* RESPONSE
    +------------+------------+
    |    USER    |   STATUS   | 
    +------------+------------+
    |  Variable  |     1      |  
    +------------+------------+
    */

    // struct users * ans = get_users_parser(response, length+1);
    // if(ans->error != NO_ERROR){
    //     printf("error\n");
    // } else {
    //     printf("Users quantity: %zu\n", ans->users_qty);
    //     for(int i = 0; i<ans->users_qty; i++){
    //         printf("User: %s\tStatus: %d\n", ans->users[i].user, ans->users[i].status);
    //     }
    // }
    // free_users(ans);
}

static void get_access_log(uint8_t *response, int length){

    /* RESPONSE
    +----------+----------+-------+----------+----------+----------+----------+----------+
    |   TIME   |   USER   | RTYPE |   OIP    |  OPORT   |   DEST   |  DPORT   |  STATUS  |
    +----------+----------+-------+----------+----------+----------+----------+----------+
    | Variable | Variable |   1   | Variable | Variable | Variable | Variable |    1     |
    +----------+----------+-------+----------+----------+----------+----------+----------+
    */

//    struct access_log * ans = get_access_log_parser(response, length+1);
//     if(ans->error != NO_ERROR){
//         printf("error\n");
//     } else {
//         printf("%zu entries:\n", ans->entry_qty);
//         for(int i = 0; i<ans->entry_qty; i++){
//             printf("\nEntry %d\n", i);
//             printf("\tTime: %s\n",ans->entries[i].time);
//             printf("\tUser: %s\n",ans->entries[i].user.user);
//             printf("\tOrigin IP: %s\n",ans->entries[i].origin_ip);
//             printf("\tOrigin port: %d\n",ans->entries[i].origin_port);
//             printf("\tDestination: %s\n",ans->entries[i].destination);
//             printf("\tDestination port: %d\n",ans->entries[i].destination_port);
//             printf("\tStatus: %u\n",ans->entries[i].user.status);
//         }
//     }
//     free_access_log(ans);
}

static void get_passwords(uint8_t *response, int length){

    /*
    +----------+----------+-------+----------+----------+----------+----------+----------+
    |   TIME   |   USER   | RTYPE | PROTOCOL |   DEST   |  DPORT   |   ULOG   | PASSWORD |
    +----------+----------+-------+----------+----------+----------+----------+----------+
    | Variable | Variable |   1   | Variable | Variable | Variable | Variable | Variable |
    +----------+----------+-------+----------+----------+----------+----------+----------+
    */

//    struct passwords * ans = get_passwords_parser(response, length+1);
//     if(ans->error != NO_ERROR){
//         printf("error\n");
//     } else {
//         printf("%zu entries:\n", ans->entry_qty);
//         for(int i = 0; i<ans->entry_qty; i++){
//             printf("\nEntry %d\n", i);
//             printf("\tTime: %s\n",ans->entries[i].time);
//             printf("\tUser: %s\n",ans->entries[i].user);
//             printf("\tProtocol: %s\n",ans->entries[i].protocol);
//             printf("\tDestination: %s\n",ans->entries[i].destination);
//             printf("\tDestination port: %d\n",ans->entries[i].destination_port);
//             printf("\tUsername: %s\n",ans->entries[i].username);
//             printf("\tPassword: %s\n",ans->entries[i].password);
//         }
//     }
    // free_passwords(ans);
}

static void get_vars(uint8_t *response, int length){

    /*
    +-------+----------+
    | VCODE |  VVALUE  |
    +-------+----------+
    |   1   | Variable |
    +-------+----------+
    */

//    struct vars * ans = get_vars_parser(response, length+1);
    // if(ans->error != NO_ERROR){
    //     printf("error\n");
    // } else {
    //     printf("IO Timeout = %lu\n", ans->io_timeout);
    // }
    // free_vars(ans);  
}

static void set_user(){
    char user[MAX_BUFFER];
    char pass[MAX_BUFFER];
    
    printf("\nEnter user data\n");
  
    printf("Username: ");
    if(fgets(buffer, sizeof(buffer), stdin) != NULL){
        buffer[strcspn(buffer, "\r\n")] = '\0';
        sscanf(buffer, "%s", user);
    }

    if(strlen(user) > 255){
        printf("Username must be shorter\n");
        return;
    }
    
    printf("Password: ");
    if(fgets(buffer, sizeof(buffer), stdin) != NULL){
        buffer[strcspn(buffer, "\r\n")] = '\0';
        sscanf(buffer, "%s", pass);
    }

    if(strlen(pass) > 255){
        printf("Password must be shorter\n");
    }

    printf("Mode: \n");
    printf("[0] Disables user to use Proxy\n");
    printf("[1] Enables user to use Proxy, creates user if it does not exists\n");
    printf("[2] Removes user\n");

    if(fgets(buffer,sizeof(buffer),stdin) == NULL){
        fprintf(stderr,"Please, choose an option.\n");
        return;
    }

    char *ptr;
    long ret;

    ret = strtoul(buffer,&ptr,10);

    if(ret == 0 || ret == 1 || ret == 2){
        
        int DATAGRAM_MAX_LENGTH = (1+2*255);
        uint8_t datagram [DATAGRAM_MAX_LENGTH];

        const uint8_t ulen = (uint8_t) strlen(user);
        const uint8_t plen = (uint8_t) strlen(pass);
        const uint8_t datalen = 4 + ulen + plen;

        datagram[0] = 0x06;
        strcpy((char *)datagram + 1,username);
        strcpy((char *)datagram + (2+ulen),password);
        datagram[datalen-1] = ret;

        int ret;
        ret = sctp_sendmsg (sd, (void *)datagram, (size_t) datalen,NULL, 0, 0, 0, 0, 0, 0);

        if(ret == -1){
            printf("Error sending request\n");
        }
    }
}

static void set_vars(){
    printf("Log Severity: \n");
    printf("[1] DEBUG\n");
    printf("[2] INFO\n");
    printf("[3] WARNING\n");
    printf("[3] ERROR\n");


    if(fgets(buffer,sizeof(buffer),stdin) == NULL){
        fprintf(stderr,"Please, choose an option.\n");
        return;
    }

    char *ptr;
    long ret;

    ret = strtoul(buffer,&ptr,10);

    if(ret == 1 || ret ==21 || ret == 3 || ret == 4){
         int DATAGRAM_MAX_LENGTH = (3);
        uint8_t datagram [DATAGRAM_MAX_LENGTH];
        datagram[0] = 0x07;
        datagram[1] = 0x02;
        datagram[2] = ret;
        
        int ret;
        ret = sctp_sendmsg (sd, (void *)datagram, (size_t) DATAGRAM_MAX_LENGTH,NULL, 0, 0, 0, 0, 0, 0);

        if(ret == -1){
            printf("Error sending request\n");
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
    printf("[6] Set users\n");
    printf("[7] Set vars\n");


    if(fgets(buffer,sizeof(buffer),stdin) == NULL){
        fprintf(stderr,"Please, choose an option.\n");
         return;
    }

    char *ptr;
    long ret;

    ret = strtoul(buffer,&ptr,10);

    switch(ret){
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
            get_command(ret);
            break;
        case 6:
            set_user();
            break;
        case 7:
            set_vars();
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