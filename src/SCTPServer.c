//
// Created by Nacho Grasso on 07/06/2020.
//

/* ----- INCLUDES ----- */

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

#include "include/SCTPServer.h"

/* ----- DEFINES ----- */
#define MAX_BUFFER 1024
#define MY_PORT_NUM 62324

int main(){
    int listenSock, connSock, ret, in, flags, i;

    /* struct sockaddr_in {
       short            sin_family;   // e.g. AF_INET
       unsigned short   sin_port;     // e.g. htons(3490)
       struct in_addr   sin_addr;     // see struct in_addr, below
       char             sin_zero[8];  // zero this if you want to
   };

   struct in_addr {
       unsigned long s_addr;  // load with inet_aton()
   }; */
    struct sockaddr_in servaddr;

    /*
     * Used to get or set the default initial parameters used on a SCTP socket when sneding out the INIT message
     * struct sctp_initmsg {
    *  uint16_t sinit_num_ostreams;     //represents the number of outbound SCTP streams an application would like to request.
     * uint16_t sinit_max_instreams;    //represents the maximum number of inbound streams the application is prepared to allow.
     * uint16_t sinit_max_attempts;     //expresses how many times the SCTP stack should send the initial INIT message before considering the endpoint unreachable.
     * uint16_t sinit_max_init_timeo;   //represents the maximum RTO value for the INIT timer.
     * }
     */
    struct sctp_initmsg initmsg;

    /*
     * Eight different types of event can be subscribed to by using this option and passing this structure.
     * Any value of 0 represents a non-subscription and a value of 1 represents a subscription
     * struct sctp_event_subscribe {
     * u_int8_t sctp_data_io_event;
     * u_int8_t sctp_association_event
     * u_int8_t sctp_address_event;
     * u_int8_t sctp_send_failure_event;
     * u_int8_t sctp_peer_error_event;
     * u_int8_t sctp_shutdown_event;
     * u_int8_t sctp_partial_delivery_event;
     * u_int8_t sctp_adaption_layer_event;
     * }
     */
    struct sctp_event_subscribe events;

    /*
     * struct sctp_sndrcvinfo {
     * uint16_ sinfo_stream;
     * uint16_ sinfo_ssn;
     * uint16_t sinfo_flags;
     * }
     */
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
    /*
     * uint32_t htonl(uint32_t hostlong)
     * function converts the unsigned integer hostlong from host byte order to network byte order.
     *
     * INADDR_ANY: For a server, you typically want to bind to all interfaces - not just "localhost".
     */
    servaddr.sin_addr.s_addr = htonl (INADDR_ANY);
    servaddr.sin_port = htons (MY_PORT_NUM);


    /*
     * Assigns the address specified by addr to the socket referred to by the file descriptor sockfd.
     * int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
     */
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

    /*
     *  int listen(int socket, int backlog);
     *  The backlog parameter defines the maximum length for the queue of pending connections.
     *  If a connection request arrives with the queue full, the client may receive an error
     */
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

        /*
         * int accept(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
         * Extracts the first connection request on the queue of pending connections.
         * Creates a new socket with the same properties of socket, and allocates a new file descriptor for the socket
         */
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

        /*
         * int sctp_recvmsg(int sd, void * msg, size_t len, struct sockaddr * from, socklen_t * fromlen, struct sctp_sndrcvinfo * sinfo, int * msg_flags);
         * Used to receive a message from a socket while using the advanced features of SCTP.
         */
        in = sctp_recvmsg (connSock, buffer, sizeof (buffer),
                           (struct sockaddr *) NULL, 0, &sndrcvinfo, &flags);

        if( in == -1)
        {
            printf("Error in sctp_recvmsg\n");
            perror("sctp_recvmsg()");
            close(connSock);
            continue;
        }
        else
        {
            //Add '\0' in case of text data
            buffer[in] = '\0';

            printf (" Length of Data received: %d\n", in);
            printf (" Data : %s\n", (char *) buffer);
        }
        close (connSock);
    }

    return 0;
}

