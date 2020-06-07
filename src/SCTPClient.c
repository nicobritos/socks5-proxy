//
// Created by Nacho Grasso on 07/06/2020.
//

/* ----- INCLUDES ----- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>

#include "include/SCTPClient.h"

/* ----- DEFINES ----- */
#define MAX_BUFFER 1024
#define MY_PORT_NUM 62324

int main(int argc, char* argv[]){

    /* struct sockaddr_in {
        short            sin_family;   // e.g. AF_INET
        unsigned short   sin_port;     // e.g. htons(3490)
        struct in_addr   sin_addr;     // see struct in_addr, below
        char             sin_zero[8];  // zero this if you want to
    };

    struct in_addr {
        unsigned long s_addr;  // load with inet_aton()
    }; */
    struct sockaddr_in servAddr; // Structures for handling internet addresses

    /* struct sctp_status {
        sctp_assoc_t sstat_assoc_id;
        int32_t sstat_state;
        u_int32_t sstat_rwnd;
        u_int16_t sstat_unackdata;
        u_int16_t sstat_penddata;
        u_int16_t sstat_instrms;
        u_int16_t sstat_outstrms;
        u_int32_t sstat_fragmentation_point;
        struct sctp_paddrinfo sstat_primary;
    }; */
    struct sctp_status status; // Current state of an SCTP association.

    char buffer[MAX_BUFFER + 1];
    int dataLength = 0;

    //------------------- Fill Buffer ------------------- //
    /*Get the input from user*/
    printf("Enter data to send: ");
    fgets(buffer, MAX_BUFFER, stdin);
    /* Clear the newline or carriage return from the end*/
    buffer[strcspn(buffer, "\r\n")] = 0;

    dataLength = strlen(buffer);

    //------------------- Send Data via Socket ------------------- //
    /*
     * socket -> creates an endpoint for communication and returns a descriptor.
     * socket(int domain, int type, int protocol);
         * domain -> The domain parameter specifies a communications domain within which communication will take place. <sys/socket.h>
            * PF_LOCAL        Host-internal protocols, formerly called PF_UNIX,
            * PF_UNIX         Host-internal protocols, deprecated, use PF_LOCAL,
            * PF_INET         Internet version 4 protocols,ecated, use PF_LOCAL,
            * PF_ROUTE        Internal Routing protocol,ls,
            * PF_KEY          Internal key-management function,
            * PF_INET6        Internet version 6 protocols,
            * PF_SYSTEM       System domain,
            * PF_NDRV         Raw access to network device
         * type -> Specifies the semantics of communication.
            * SOCK_STREAM     Sequenced, reliable, two-way connection based byte streams.
            * SOCK_DGRAM      Supports datagrams (connectionless, unreliable messages of a fixed (typically small) maximum length)
            * SOCK_RAW        Provide access to internal network protocols and interfaces.
         * protocol -> Particular protocol to be used with the socket
            * IPPROTO_UDP
            * IPPROTO_TCP
            * IPPROTO_SCTP
    */
    int connSock = socket (PF_INET, SOCK_STREAM, IPPROTO_SCTP); //estoy usando IPV4
    if(connSock == -1){
        //No se pudo crear el socket
        printf("Socket creation failed\n");
        perror("socket()");
        exit(1);
    }
    /* bzero(void *s, size_t n);
     * Function writes n zeroed bytes to the string s. If n is zero, bzero() does nothing.
    */
    bzero ((void *) &servaddr, sizeof (servaddr));

    servaddr.sin_family = PF_INET; //estoy usando IPV4

    /*  uint16_t htons(uint16_t hostshort);
     * function converts the unsigned short integer hostshort from host byte order to network byte order.
     *  Network-Byte-Order is a standard way to represent multi-byte values so that communication can take place across
     *  a network without having to know the "endianness" of the two machines communicating.
     */
    servaddr.sin_port = htons(MY_PORT_NUM); //

    /* in_addr_t inet_addr(const char *cp);
     * converts the Internet host address cp from IPv4 numbers-and-dots notation into binary data in network byte order.
     * If the input is invalid, INADDR_NONE (usually -1) is returned. Use of this function is problematic because -1
     * is a valid address (255.255.255.255).
     * Alternative inet_aton(), inet_pton(3), or getaddrinfo(3) which provide a cleaner way to indicate error return.
     */
    servaddr.sin_addr.s_addr = inet_addr ("127.0.0.1");

    /*  int connect(int socket, const struct sockaddr *address, socklen_t address_len);
     * Upon successful completion, a value of 0 is returned.  Otherwise, a value of -1 is returned and the global
     * integer variable errno is set to indicate the error.
     */
    int ret = connect (connSock, (struct sockaddr *) &servaddr, sizeof (servaddr));

    if (ret == -1)
    {
        //No se pudo establecer la conexion
        printf("Connection failed\n");
        perror("connect()");
        close(connSock);
        exit(1);
    }
    /* int sctp_sendmsg(int sd, const void * msg, size_t len,struct sockaddr *to, socklen_t tolen,
     * uint32_t ppid, uint32_t flags, uint16_t stream_no, uint32_t timetolive, uint32_t context);
     * Is a wrapper library function that can be used to send a message from a socket while using the advanced features of SCTP.
     * On success, sctp_sendmsg returns the number of bytes sent or -1 if an error occurred.
     */
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

