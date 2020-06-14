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
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>

#include "include/SCTPClient.h"

#define MAX_BUFFER 1024
#define MY_PORT_NUM 62324
#define HISTORICAL_CONNECTION 1
#define CONCURRENT_CONNECTIOS 2
#define BYTES_TRANSFERRED 3

static int connSock;

int main(int argc, char* argv[]){

    struct sockaddr_in servaddr; // Structures for handling internet addresses
    char buffer[MAX_BUFFER + 1];
    int dataLength = 0;

    /*Get the input from user*/
    printf("Enter data to send: ");
    fgets(buffer, MAX_BUFFER, stdin);
    /* Clear the newline or carriage return from the end*/
    buffer[strcspn(buffer, "\r\n")] = 0;

    dataLength = strlen(buffer);


    connSock = socket (PF_INET, SOCK_STREAM, IPPROTO_SCTP); //estoy usando IPV4
    if(connSock == -1){
        //No se pudo crear el socket
        printf("Socket creation failed\n");
        perror("socket()");
        exit(1);
    }

    bzero((void *) &servaddr, sizeof (servaddr));

    servaddr.sin_family = PF_INET; //estoy usando IPV4
    servaddr.sin_port = htons(MY_PORT_NUM); //
    servaddr.sin_addr.s_addr = inet_addr ("127.0.0.1");


    int ret = connect (connSock, (struct sockaddr *) &servaddr, sizeof (servaddr));

    if (ret == -1)
    {
        //No se pudo establecer la conexion
        printf("Connection failed\n");
        perror("connect()");
        close(connSock);
        exit(1);
    }

    ret = sctp_sendmsg (connSock, (void *) buffer, (size_t) dataLength,NULL, 0, 0, 0, 0, 0, 0);

    if(ret == -1 )
    {
        printf("Error in sctp_sendmsg\n");
        perror("sctp_sendmsg()");
    }
    else
        printf("Successfully sent %d bytes data to server\n", ret);

    close (connSock);

    return 0;

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
    uint8_t datagram[1]
    int ret;


}