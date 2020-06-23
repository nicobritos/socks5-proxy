//
// Created by Nacho Grasso on 07/06/2020.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <stdbool.h>
#include <netdb.h>
#include <limits.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>

#include "MonitorServer.h"
#include "args.h"
#include "socks5/sniffer/sniffed_credentials.h"
#include "socks5/message/auth_user_pass_helper.h"
#include "utils/log_helper.h"
#include "socks5/socks5nio.h"
#include "monitor_parser/server/command_request_parser.h"
#include "monitor_parser/server/proxy_credentials_parser.h"

#define MAX_BUFFER 1024
#define MY_PORT_NUM 57611

char *address = "127.0.0.1";
uint16_t port = 57611;
static bool logged = true;
static char *user = "admin";
static char *password = "adminadmin";
static char buffer[MAX_BUFFER];
static struct addrinfo *res;
static struct socks5args args;
int listenSock;
int connSock;



static bool authenticate_user(char *buffer, int length){
    struct proxy_credentials * ans = proxy_credentials_parser(buffer, length);
    free(buffer);
    if(ans->error != 0){
        printf("error\n");
    } else {
        printf("%u\n", ans->version);
        printf("%s\n", ans->username);
        printf("%s\n", ans->password);
    }

    if( strcmp(user,ans->username) == 0){
        if(strcmp(password,ans->password) == 0){
            logged = true;
        }
    }
    proxy_credentials_free(ans);
    return logged;
}

static void server_init(){
    struct sockaddr_in addr;
    struct addrinfo hint;
    int ret,domain;

    memset(&addr, 0, sizeof(addr));
    memset(&hint, 0, sizeof hint);
    addr.sin_port  = htons(args.mng_port);
    hint.ai_family = AF_UNSPEC;
    hint.ai_flags  = AI_NUMERICHOST;

    ret = getaddrinfo(args.mng_addr, NULL, &hint, &res);

    if (ret) {
        printf("Invalid address\n");
        exit(EXIT_FAILURE);
    }
    if (res->ai_family == AF_INET) {
        domain = AF_INET;
        addr.sin_family = AF_INET;
        if (inet_pton(AF_INET, args.mng_addr, &addr.sin_addr) != 1) {
            exit(EXIT_FAILURE);
        }
    } else if (res->ai_family == AF_INET6) {
        domain = AF_INET6;
        addr.sin_family = AF_INET6;
        if (inet_pton(AF_INET6, args.mng_addr, &addr.sin_addr) != 1) {
            exit(EXIT_FAILURE);
        }
    } else {
        printf("Invalid address\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    listenSock = socket(domain, SOCK_STREAM, IPPROTO_SCTP);

    if(listenSock < 0) {
        fprintf(stderr,"Error creating socket with the server using %s:%hu\n",args.mng_addr,args.mng_port);
        exit(EXIT_FAILURE);
    }

    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));

    if(bind(listenSock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        fprintf(stderr,"Unable to bind socket\n");
        exit(EXIT_FAILURE);
    }

    if(listen(listenSock, 1) < 0) {
        fprintf(stderr,"Unable to listen\n");
        exit(EXIT_FAILURE);
    }
}

static int receive_request(){
    int in, flags;
    struct sctp_sndrcvinfo sndrcvinfo;

    //Clear the buffer
    bzero (buffer, MAX_BUFFER);

    printf ("Listening...\n");

    connSock = accept(listenSock, (struct sockaddr *) NULL, (socklen_t *) NULL);
    if (connSock == -1)
    {
        printf("accept() failed\n");
        perror("accept()");
        close(connSock);
        return connSock;
    }
    
    printf ("New connection received\n");

    in = sctp_recvmsg(connSock, buffer, sizeof (buffer),(struct sockaddr *) NULL, 0, &sndrcvinfo, &flags);
    if( in == -1)
    {
        printf("Error in sctp_recvmsg\n");
        perror("sctp_recvmsg()");
        close(connSock);
    }
    return in;
}

static void sign_in(char *buffer, int length){
    uint8_t response[MAX_BUFFER];
    char message[255];
    bool userAuth = authenticate_user(buffer,length);
    if(userAuth){
        printf("User:%s has signned in.\n",user);
        response[0] = 0x01;
        strcpy(message,"Welcome!");
    }
    else{
        printf("Failed authentication\n");
        response[0] = 0x00;
        strcpy(message,"Username Or Password Incorrect");
    }

    strcpy((char *)response+1,message);    

    int ret = sctp_sendmsg(connSock, (void *) response, (size_t) sizeof(uint8_t)*(strlen(message)+2),NULL, 0, 0, 0, 0, 0, 0);
    if(ret == -1){
        printf("Error sending message\n");
    }
}

static void get_metrics(){

    /* RESPONSE
    +------+------+-------+
    | ECON | ACON | BYTES | 
    +------+------+-------+
    |   8  |   8  |   8   |  
    +------+------+-------+
    */

    const int RESPONSE_MAX_LENGTH = 24;
    uint8_t response[RESPONSE_MAX_LENGTH];

    // uint64_t tc = socks_get_total_connections();
    // uint64_t cc = socks_get_current_connections();
    // uint64_t tbt = sockes_get_total_bytes_transferred();

    // FALTA -> HACER LA CONVERSION DE uint64_t a uint8_t[8] Y AGREGARLOS AL RESPONSE;

    int ret = sctp_sendmsg(connSock, (void *) response, (size_t) sizeof(uint8_t)*RESPONSE_MAX_LENGTH,NULL, 0, 0, 0, 0, 0, 0);
    if(ret == -1){
        printf("Error sending message\n");
    }
}

static void get_users(){

    /* RESPONSE
    +------------+------------+
    |    USER    |   STATUS   | 
    +------------+------------+
    |  Variable  |     1      |  
    +------------+------------+
    */

    const int RESPONSE_MAX_LENGTH = 1024;
    uint8_t response[RESPONSE_MAX_LENGTH];

    sorted_hashmap_list_t aup = auth_user_pass_get_values();
    if(aup != NULL){
        int length = 0;
        sorted_hashmap_list_node_t node = sorted_hashmap_list_get_first(aup);
        while(node != NULL){
            struct auth_user_pass_credentials *credentials = sorted_hashmap_list_get_element(node);
            strcpy((char *)response+length,credentials->username);
            length += (credentials->username_length + 1);
            response[length] = credentials->active;
            length += 1;

            node = sorted_hashmap_list_get_next_node(node);
        }
        response[length] = '\0';
    }

    sorted_hashmap_list_free(aup);

    int ret = sctp_sendmsg(connSock, (void *) response, (size_t) sizeof(uint8_t)*RESPONSE_MAX_LENGTH,NULL, 0, 0, 0, 0, 0, 0);
    if(ret == -1){
        printf("Error sending message\n");
    }

}

static void get_access_log(){

    /* RESPONSE
    +----------+----------+-------+----------+----------+----------+----------+----------+
    |   TIME   |   USER   | RTYPE |   OIP    |  OPORT   |   DEST   |  DPORT   |  STATUS  |
    +----------+----------+-------+----------+----------+----------+----------+----------+
    | Variable | Variable |   1   | Variable | Variable | Variable | Variable |    1     |
    +----------+----------+-------+----------+----------+----------+----------+----------+
    */

    const int RESPONSE_MAX_LENGTH = 2048;
    uint8_t response[RESPONSE_MAX_LENGTH];

   socks_access_log_node_t log_node = socks_get_first_access_log_node();
   int length = 0;
   while(log_node != NULL){
       struct socks_access_log_details_t  *details =  socks_get_access_log(log_node);
       strcpy((char *)response+length,details->datetime);
       length += (strlen(details->datetime) + 1);
       strcpy((char *)response+length,details->username);
       length += (strlen(details->username) + 1);
       strcpy((char *)response+length, "A");
       length += (strlen("A") + 1);
       strcpy((char *)response,details->origin.ip);
       length += (strlen(details->origin.ip) + 1);
       strcpy((char *)response,details->origin.port);
       length += (strlen(details->origin.port) + 1);
       strcpy((char *)response, details->destination.name);
       length += (strlen(details->destination.name) + 1);
       strcpy((char *)response, details->destination.port);
       length += (strlen(details->destination.port) + 1);
       response[length] = details->status;
       length += sizeof(details->status);
       response[length] = '\0';
       length += 1;
       response[length] = '\0';
       length += 1;
   }
   response[length] = '\0';

   int ret = sctp_sendmsg(connSock, (void *) response, (size_t) sizeof(uint8_t)*RESPONSE_MAX_LENGTH,NULL, 0, 0, 0, 0, 0, 0);
    if(ret == -1){
        printf("Error sending message\n");
    }
}

static void get_passwords(){

    /* RESPONSE
    +----------+----------+-------+----------+----------+----------+----------+----------+
    |   TIME   |   USER   | RTYPE | PROTOCOL |   DEST   |  DPORT   |   ULOG   | PASSWORD |
    +----------+----------+-------+----------+----------+----------+----------+----------+
    | Variable | Variable |   1   | Variable | Variable | Variable | Variable | Variable |
    +----------+----------+-------+----------+----------+----------+----------+----------+
    */

    const int RESPONSE_MAX_LENGTH = 2048;
    uint8_t response[RESPONSE_MAX_LENGTH];

    sniffed_credentials_list scl = socks_get_sniffed_credentials_list();

    if(scl != NULL){
        int length=0;
        sniffed_credentials_node node = sniffed_credentials_get_first(scl);
        while(node != NULL){
            struct sniffed_credentials * credential = sniffed_credentials_get(node);

            strcpy((char *)response+length,credential->datetime);
            length += (strlen(credential->datetime)+1);
            strcpy((char *)response+length,credential->username); 
            length += (strlen(credential->username)+1);
            strcpy((char *)response+length,"P"); 
            length += (strlen("P")+1);
            strcpy((char *)response+length,credential->protocol); 
            length += (strlen(credential->protocol)+1);
            strcpy((char *)response+length,credential->destination); 
            length += (strlen(credential->destination)+1);
            strcpy((char *)response+length,credential->port); 
            length += (strlen(credential->port)+1);
            strcpy((char *)response+length,credential->logger_user); 
            length += (strlen(credential->logger_user)+1);
            strcpy((char *)response+length,credential->password); 
            length += (strlen(credential->password)+1);
            response[length] = '\0';
            length += 1;

            node = sniffed_credentials_get_next(node);
        }
        response[length] = '\0';
    }

    sniffed_credentials_destroy(scl);

    int ret = sctp_sendmsg(connSock, (void *) response, (size_t) sizeof(uint8_t)*RESPONSE_MAX_LENGTH,NULL, 0, 0, 0, 0, 0, 0);
    if(ret == -1){
        printf("Error sending message\n");
    }
}

static void get_vars(){

    /*
    +-------+----------+
    | VCODE |  VVALUE  |
    +-------+----------+
    |   1   | Variable |
    +-------+----------+
    */

    int RESPONSE_MAX_LENGTH = 2;
    uint8_t response[RESPONSE_MAX_LENGTH];
    
    log_t log = logger_get_system_log();

    if(log != NULL){
        response[0] = 0x02;
        enum log_severity log_sev = logger_get_log_severity(log);
        response[1] = log_sev;
    }

    int ret = sctp_sendmsg(connSock, (void *) response, (size_t) sizeof(uint8_t)*RESPONSE_MAX_LENGTH,NULL, 0, 0, 0, 0, 0, 0);
    if(ret == -1){
        printf("Error sending message\n");
    }

}

static void set_user(char *username, char *password, user_mode mode){
    enum auth_user_pass_helper_status status;
    if(mode == REMOVE_USER){
        status = auth_user_pass_helper_remove(username);
        if(status != auth_user_pass_helper_status_ok ){
            printf("Error trying to  delete user. Status code: %d\n",status);
            return;
        }
    }
    else{
        status = auth_user_pass_helper_set_enable(username,mode);
        if((status == auth_user_pass_helper_status_error_user_not_found) && mode == ENABLE_USER ){
            struct auth_user_pass_credentials *credentials = malloc(sizeof(*credentials));
            if(credentials != NULL){
                uint8_t length = strlen(username);
                credentials->username = malloc(sizeof(*credentials->username) * length + 1);
    
                if(credentials->username == NULL) {
                    free(credentials);
                    return;
                }

                 memcpy(credentials->username,username,length + 1);

                credentials->username_length = length;

                length = strlen(password);
                credentials->password = malloc(sizeof(*credentials->password) * length +1);

                if(credentials->password == NULL){
                    free(credentials->username);
                    free(credentials);
                }

                memcpy(credentials->password,password,length + 1);
                credentials->active = mode;

                status = auth_user_pass_helper_add(credentials);
                if(status != auth_user_pass_helper_status_ok){
                    printf("Error trying to add new user. Status code: %d\n",status);
                    return;
                }
            }
        }
        if(status != auth_user_pass_helper_status_ok){
            printf("Error trying to enable/disable user. Status code: %d\n",status);
            return;
        }
    }
    printf("Set_user():Finished with no errors\n");
}

static void set_vars(var_code var, uint8_t * var_value){
    if(var == LMODE){
        log_t log = logger_get_system_log();
        if(log != NULL){
            logger_set_log_severity(log,(char)var_value);
        }
    }
}
    

static void parse_command(char *buffer, int length){
    if(strlen(buffer) == 1){
        uint8_t code = buffer[0];

        switch(code){
            case 0x01:
                get_metrics();
                break;
            case 0x02:
                printf("GET_USERS\n");
                get_users();
                break;
            case 0x03:
                printf("GET_ACCESS_LOG\n");
                get_access_log();
                break;
            case 0x04:
                printf("GET_PASSWORDS\n");
                get_passwords();
                break;
            case 0x05:
                printf("GET_VARS\n");
                get_vars();
                break;
            default:
                break;
        }
    }
    else{
        struct command * ans = command_request_parser(buffer, length);
        if(ans->error != NO_ERROR){
            printf("error\n");
        } else {
            if(ans->code == SET_USER){
                set_user(ans->user,ans->password,ans->mode);
                printf("User = %s\n", ans->user);
                printf("Password = %s\n", ans->password);
                printf("Mode = %u\n", ans->mode);
            } else if(ans->code == SET_VAR){
                set_vars(ans->var,ans->var_value);
                printf("Var Code = %u\n", ans->var);
                for(int i = 0; i<ans->var_value_length; i++){
                    printf("Var Value - Byte %d = %02x\n", i, ans->var_value[i]);
                }
            }
        }
        free_command(ans);
    }
    
}


int main(int argc, char* argv[]){

    parse_args(argc,argv,&args);
    server_init();

    while (1)
    {
        int ret = receive_request();
        if(ret > 0){
            if(!logged){
                sign_in(buffer,ret);
            }
            else{
                parse_command(buffer,ret);
            }
        }
        else{
            close(connSock);            
        }
    }
    return 0;
}

