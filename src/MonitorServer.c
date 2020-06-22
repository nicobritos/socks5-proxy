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

#define MAX_BUFFER 1024
#define MY_PORT_NUM 57611

char *address = "127.0.0.1";
uint16_t port = 57611;
static bool logged = false;
static char *user = "admin";
static char *password = "adminadmin";
static char buffer[MAX_BUFFER];
static struct addrinfo *res;
static struct socks5args args;
int listenSock;



static bool authenticate_user(char *buffer){
    uint8_t userRec[MAX_BUFFER];
    uint8_t passRec[MAX_BUFFER];

    strcpy(userRec,buffer+1);
    strcpy(passRec,buffer+2+strlen(userRec));

    if( strcmp(user,userRec) == 0){
        if(strcmp(password,passRec) == 0){
            logged = true;
        }
    }
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


int main(int argc, char* argv[]){
    int connSock, ret, in, flags, i;
    struct sockaddr_in servaddr;
    struct sctp_initmsg initmsg;
    struct sctp_event_subscribe events;
    struct sctp_sndrcvinfo sndrcvinfo;
    char buffer[MAX_BUFFER];
    parse_args(argc,argv,&args);
    server_init();

    while (1)
    {
        //Clear the buffer
        bzero (buffer, MAX_BUFFER);

        printf ("Awaiting a new connection\n");

        connSock = accept(listenSock, (struct sockaddr *) NULL, (socklen_t *) NULL);
        if (connSock == -1)
        {
            printf("accept() failed\n");
            perror("accept()");
            close(connSock);
            continue;
        }
        else
            printf ("New client connected....\n");

        in = sctp_recvmsg (connSock, buffer, sizeof (buffer),(struct sockaddr *) NULL, 0, &sndrcvinfo, &flags);

        if( in == -1)
        {
            printf("Error in sctp_recvmsg\n");
            perror("sctp_recvmsg()");
            close(connSock);
            continue;

        }
        else{
            if(!logged){
                uint8_t response[255];
                bool userAuth = authenticate_user(buffer);
                if(userAuth){
                    printf("%s has signned in!\n",user);
                    response[0] = 0x01;
                    char *welcome = "Welcome!";
                    strcpy(response+1,welcome);
                    response[1+strlen(welcome)] = '\0';
                }
                else{
                    printf("Failed authentication\n");
                    response[0] = 0x00;
                    char *errorAuth = "Username or Password incorrect";
                    strcpy(response+1,errorAuth);
                    response[1+strlen(errorAuth)] = '\0';
                }
                int ret = sctp_sendmsg(connSock, (void *) response, (size_t) sizeof(uint8_t)*strlen(response),NULL, 0, 0, 0, 0, 0, 0);
                if(ret == -1){
                    printf("Error sending message\n");
                }
            }
            else{
                uint8_t code = buffer[0];
                switch(code){
                    case 0x01:
                        printf("GET_METRICS\n");
                        // get_metrics();
                        break;
                    case 0x02:
                        printf("GET_USERS\n");
                        // get_users();
                        break;
                    case 0x03:
                        printf("GET_ACCESS_LOG\n");
                        // get_acces_log();
                        break;
                    case 0x04:
                        printf("GET_PASSWORDS\n");
                        // get_passwords();
                        break;
                    case 0x05:
                        printf("GET_VARS\n");
                        // get_vars();
                        break;
                    default:
                        break;
                }
            }
        }
        close(connSock);            
    }
    return 0;
}

