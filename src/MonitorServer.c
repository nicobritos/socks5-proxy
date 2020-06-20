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

#include "include/MonitorServer.h"

#define MAX_BUFFER 1024
#define MY_PORT_NUM 62324

static char *user = "admin";
static char *password = "adminadmin";

static bool authenticate_user(char *buffer){
    uint8_t ulen = buffer[1];
    uint8_t plen = buffer[1+ulen];
    uint8_t userRec[MAX_BUFFER];
    uint8_t passRec[MAX_BUFFER];

    strncpy(userRec,buffer+2,ulen);
    userRec[ulen] = '\0';
    printf("%s\n",userRec);

    strncpy(passRec,buffer+2+ulen+1,plen);
    passRec[plen] = '\0';
    printf("%s\n",passRec);

    if( strcmp(user,userRec) == 0){
        if(strcmp(password,passRec) == 0){
            return true;
        }
    }
    return false;
}

int main(){
    int listenSock, connSock, ret, in, flags, i;
    struct sockaddr_in servaddr;
    struct sctp_initmsg initmsg;
    struct sctp_event_subscribe events;
    struct sctp_sndrcvinfo sndrcvinfo;
    char buffer[MAX_BUFFER + 1];

    listenSock = socket (AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if(listenSock == -1)
    {
        printf("Failed to create socket\n");
        perror("socket()");
        exit(1);
    }

    bzero((void *) &servaddr, sizeof (servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl (INADDR_ANY);
    servaddr.sin_port = htons (MY_PORT_NUM);

    ret = bind (listenSock, (struct sockaddr *) &servaddr, sizeof (servaddr));

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
    ret = setsockopt (listenSock, IPPROTO_SCTP, SCTP_INITMSG,
                      &initmsg, sizeof (initmsg));

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
        char buffer[MAX_BUFFER + 1];
        int len;

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
            buffer[in] = '\0';
            if(buffer[0] == 0x01){
                bool userAuth = authenticate_user(buffer);
                uint8_t response[2];
                int length;
                if(userAuth){
                    printf("Username: %s has login!!\n",user);   
                    response[0] = 0x00;  
                    char *message = "Helloadmin";        
                    length = strlen(message);      
                    for(int i=0 ; i<length ; i++){
                        response[1 + i] = (uint8_t) message[i];
                    }
                    response[1+length] = '\0';
                }
                else{
                    response[0] = 0x01;
                }
                int ret = sctp_sendmsg(connSock, (void *) response, (size_t) 1+length,NULL, 0, 0, 0, 0, 0, 0);
                if(ret == -1){
                    //ERROR
                    printf("Error sending message\n");
                }
            }
            printf (" Length of Data received: %d\n", in);

        }            
    }
    return 0;
}

