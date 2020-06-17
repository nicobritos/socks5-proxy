#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "Practical.h"
#include "http_response_parser.h"
#include "doh.h"

uint8_t * buffer[BUFSIZE];


// socket online for testing (sacado de Echoclient non bloquing campus)
ssize_t send_query(uint8_t * query, size_t req_len){
    // Create a reliable, stream socket using TCP
  ssize_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0)
    DieWithSystemMessage("socket() failed");
  // Construct the server address structure
  struct sockaddr_in servAddr;            // Server address
  memset(&servAddr, 0, sizeof(servAddr)); // Zero out structure
  servAddr.sin_family = AF_INET;          // IPv4 address family
  // Convert address
  ssize_t rtnVal = inet_pton(AF_INET, DNS_SERVER_IP, &servAddr.sin_addr.s_addr);
  if (rtnVal == 0)
    DieWithUserMessage("inet_pton() failed", "invalid address string");
  else if (rtnVal < 0)
    DieWithSystemMessage("inet_pton() failed");
  servAddr.sin_port = htons(DNS_SERVER_PORT);    // Server port

  // Establish the connection to the echo server
  if (connect(sock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0)
    DieWithSystemMessage("connect() failed");

  // Send the string to the server
  ssize_t numBytes = send(sock, query, req_len, 0);
  if (numBytes < 0)
    DieWithSystemMessage("send() failed");
  else if (numBytes != req_len)
    DieWithUserMessage("send()", "sent unexpected number of bytes");

  // Receive the same string back from the server
  ssize_t totalBytesRcvd = 0; // Count of total bytes received
  fputs("Received: ", stdout);     // Setup to prsize_t the echoed string
  
  while (totalBytesRcvd < req_len) {
    /* Receive up to the buffer size (minus 1 to leave space for
     a null terminator) bytes from the sender */
    numBytes = recv(sock, buffer, BUFSIZE - 1, 0);
    if (numBytes < 0)
      DieWithSystemMessage("recv() failed");
    else if (numBytes == 0)
      DieWithUserMessage("recv()", "connection closed prematurely");
    totalBytesRcvd += numBytes; // Keep tally of total bytes
  }
   close(sock);

   return totalBytesRcvd;
}



int main(){
    ssize_t bytes = 0;
    uint8_t * myrequest = getRequest(&bytes,(uint8_t * ) "facebook.com", IPV6_VER);
    for (ssize_t i = 0; i < bytes; i++)
    {
        printf("0x%x ",myrequest[i]);
    }
    printf("\ntotal bytes: %d\n", bytes);
        for (ssize_t i = 0; i < bytes; i++)
    {
        printf("%c",myrequest[i]);
    }
    printf("\n");

    ssize_t bytes_res = send_query(myrequest,bytes);
    
    struct http_response * answer = http_response_parser(buffer,bytes_res);

    printf("code: %d\n", answer->status_code);
    printf("ipv4qty: %d\n", answer->ipv4_qty);

    for (size_t i = 0; i < answer->ipv4_qty ; i++){
        for (size_t k = 0; k < IP_4_BYTES; k++){
            printf("%d.",answer->ipv4_addr[i].byte[k]);
                }
   printf("\n"); 
  }

  printf("ipv6qty: %d\n", answer->ipv6_qty);
      for (size_t i = 0; i < answer->ipv6_qty ; i++){
        for (size_t k = 0; k < IP_6_BYTES; k++){
            printf("%04hx",answer->ipv6_addr[i].byte[k]);
            if(k%2==0){
                printf(":");
            }
                }
   printf("\n"); 
  }
    

}