#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "Practical.h"

#define CHUNK 50

//char http_header[] = "POST / HTTP/1.1\nHost: doh\nUser-Agent: curl-doh/1.0\nConnection: Upgrade, HTTP2-Settings\nUpgrade: h2c\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\nContent-Type: application/dns-message\nAccept: application/dns-message\nContent-Length: ";
unsigned char http_header[] = {0x50, 0x4f, 0x53, 0x54, 0x20, 0x2f, 0x20, 0x48, 
0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 
0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x64, 
0x6f, 0x68, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 
0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 
0x63, 0x75, 0x72, 0x6c, 0x2d, 0x64, 0x6f, 0x68, 
0x2f, 0x31, 0x2e, 0x30, 0x0d, 0x0a, 0x43, 0x6f, 
0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 
0x3a, 0x20, 0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 
0x65, 0x2c, 0x20, 0x48, 0x54, 0x54, 0x50, 0x32, 
0x2d, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 
0x73, 0x0d, 0x0a, 0x55, 0x70, 0x67, 0x72, 0x61, 
0x64, 0x65, 0x3a, 0x20, 0x68, 0x32, 0x63, 0x0d, 
0x0a, 0x48, 0x54, 0x54, 0x50, 0x32, 0x2d, 0x53, 
0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x3a, 
0x20, 0x41, 0x41, 0x4d, 0x41, 0x41, 0x41, 0x42, 
0x6b, 0x41, 0x41, 0x52, 0x41, 0x41, 0x41, 0x41, 
0x41, 0x41, 0x41, 0x49, 0x41, 0x41, 0x41, 0x41, 
0x41, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 
0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 
0x20, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 
0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x64, 0x6e, 0x73, 
0x2d, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 
0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 
0x3a, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 
0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x64, 0x6e, 
0x73, 0x2d, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 
0x65, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 
0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 
0x68, 0x3a, 0x20};
//unsigned char dns_header[] = {0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00}; 
unsigned char dns_header[] = {0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00};
unsigned char dns_end[] = {0x00, 0x01, 0x00, 0x01};


int bincopy(char * target, char *source, int from, int n){
size_t i = from;
size_t j = 0;
for (; i < (from + n); i++)
{
  target[i]=source[j++];
}
return i;
}

char * encodeName(int * size, char * name){
    // Back up name 
    size_t name_len = strlen(name);
    char aux[name_len];
    strcpy(aux,name);

    char qname[CHUNK][CHUNK];
    size_t j = 0;

   // Extract the first token
   char * token = strtok(aux, ".");
   // loop through the string to extract all other tokens
   while( token != NULL ) {
      sprintf(qname[j++],"%s", token );
      //printf("%s\n", token ); //printing each token
      token = strtok(NULL, ".");
   }
    
    char * result = malloc(CHUNK);
    size_t k = 0;
    for (size_t i = 0; i < j; i++){
    size_t sub_len = strlen(qname[i]);
    result[k++] = sub_len;
    bincopy(result+k,qname[i],0,sub_len);
    k+=sub_len;
    }
    result[k++]=0;

    *size = k;
    result = realloc(result,k);
    return result;
}



size_t getRequest (int * len, char * name){
  char * request = malloc(300);
  size_t i = 0;
  i = bincopy(request,http_header,i,sizeof(http_header));

  // encode name into dns message format 
  int qname_len=0;
  char * qname = encodeName(&qname_len,name);
  //int dns_message_len = sizeof(dns_header) + qname_len + sizeof(dns_end);
  int dns_message_len = (sizeof(dns_header) + qname_len + sizeof(dns_end) - 4);
  char string_len[CHUNK]={0};
  i = bincopy(request,string_len,i,sprintf(string_len,"%d",dns_message_len));
  //request[i++]='3';
  //request[i++]='5';
  i = bincopy(request,dns_header,i,sizeof(dns_header));

  i = bincopy(request,qname,i,qname_len);
  i = bincopy(request,dns_end,i,sizeof(dns_end));
  
  request = realloc(request,i);
  *len = i;
  return request;
}

int main(int argc, char *argv[]) {

  char *servIP = "127.0.0.1";
  int servPort = 80;
  
  int req_len =0;
  char * echoString = getRequest(&req_len,"itba.edu.ar");


  // Create a reliable, stream socket using TCP
  int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0)
    DieWithSystemMessage("socket() failed");

  // Construct the server address structure
  struct sockaddr_in servAddr;            // Server address
  memset(&servAddr, 0, sizeof(servAddr)); // Zero out structure
  servAddr.sin_family = AF_INET;          // IPv4 address family
  // Convert address
  int rtnVal = inet_pton(AF_INET, servIP, &servAddr.sin_addr.s_addr);
  if (rtnVal == 0)
    DieWithUserMessage("inet_pton() failed", "invalid address string");
  else if (rtnVal < 0)
    DieWithSystemMessage("inet_pton() failed");
  servAddr.sin_port = htons(servPort);    // Server port

  // Establish the connection to the echo server
  if (connect(sock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0)
    DieWithSystemMessage("connect() failed");

  size_t echoStringLen = req_len; // Determine input length

  // Send the string to the server
  ssize_t numBytes = send(sock, echoString, echoStringLen, 0);
  if (numBytes < 0)
    DieWithSystemMessage("send() failed");
  else if (numBytes != echoStringLen)
    DieWithUserMessage("send()", "sent unexpected number of bytes");

  // Receive the same string back from the server
  unsigned int totalBytesRcvd = 0; // Count of total bytes received
  fputs("Received: ", stdout);     // Setup to print the echoed string
  while (totalBytesRcvd < echoStringLen) {
    char buffer[BUFSIZE]; // I/O buffer
    /* Receive up to the buffer size (minus 1 to leave space for
     a null terminator) bytes from the sender */
    numBytes = recv(sock, buffer, BUFSIZE - 1, 0);
    if (numBytes < 0)
      DieWithSystemMessage("recv() failed");
    else if (numBytes == 0)
      DieWithUserMessage("recv()", "connection closed prematurely");
    totalBytesRcvd += numBytes; // Keep tally of total bytes
    buffer[numBytes] = '\0';    // Terminate the string!
    fputs(buffer, stdout);      // Print the echo buffer
  }

  fputc('\n', stdout); // Print a final linefeed

  close(sock);
  exit(0);
}
