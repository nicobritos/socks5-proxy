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

#include "include/MonitorClient.h"

#define MAX_BUFFER 1024
#define MY_PORT_NUM 62324
#define HISTORICAL_CONNECTION 1
#define CONCURRENT_CONNECTIOS 2
#define BYTES_TRANSFERRED 3

static int connSock;


int main(int argc, char* argv[]){

    start_connection(argc,argv);

    while(1){

        //loggear al usuario

        get_metrics();

    }

}

static void start_connection(int argc, char* argv[]){

    connSock = socket (AF_UNSPEC, SOCK_STREAM, IPPROTO_SCTP); //estoy usando IPV4
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

    //deberia enviar hello????

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