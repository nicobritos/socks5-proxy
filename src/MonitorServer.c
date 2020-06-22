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

#include "MonitorServer.h"

#define MAX_BUFFER 1024
#define MY_PORT_NUM 57610

static bool logged = false;
static char *user = "admin";
static char *password = "adminadmin";
static char buffer[MAX_BUFFER];


static bool authenticate_user(char *buffer){
    uint8_t ulen = buffer[1];
    uint8_t plen = buffer[1+ulen];
    uint8_t userRec[MAX_BUFFER];
    uint8_t passRec[MAX_BUFFER];



    strcpy(userRec,buffer+1);
    printf("%s\n",userRec);

    strcpy(passRec,buffer+2+strlen(userRec));
    printf("%s\n",passRec);

    if( strcmp(user,userRec) == 0){
        if(strcmp(password,passRec) == 0){
            logged = true;
        }
    }
    return logged;
}

int main(){
    int listenSock, connSock, ret, in, flags, i;
    struct sockaddr_in servaddr;
    struct sctp_initmsg initmsg;
    struct sctp_event_subscribe events;
    struct sctp_sndrcvinfo sndrcvinfo;
    char buffer[MAX_BUFFER + 1];

    listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if(listenSock == -1)
    {
        printf("Failed to create socket\n");
        perror("socket()");
        exit(1);
    }

    bzero((void *) &servaddr, sizeof (servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(MY_PORT_NUM);

    ret = bind(listenSock, (struct sockaddr *) &servaddr, sizeof (servaddr));

    if(ret == -1 )
    {
        printf("Bind failed \n");
        perror("bind()");
        close(listenSock);
        exit(1);
    }

    /* Specify that a maximum of 5 streams will be available per socket */
    memset (&initmsg, 0, sizeof (initmsg));
    initmsg.sinit_num_ostreams = 5;
    initmsg.sinit_max_instreams = 5;
    initmsg.sinit_max_attempts = 4;
    ret = setsockopt(listenSock, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof (initmsg));

    if(ret == -1 )
    {
        printf("setsockopt() failed \n");
        perror("setsockopt()");
        close(listenSock);
        exit(1);
    }

    ret = listen (listenSock, 5);
    if(ret == -1 )
    {
        printf("listen() failed \n");
        perror("listen()");
        close(listenSock);
        exit(1);
    }

    while (1)
    {
        //Clear the buffer
        bzero (buffer, MAX_BUFFER + 1);

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

