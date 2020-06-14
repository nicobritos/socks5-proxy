#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "Practical.h"
//#include "doh.h"

#define DNS_SERVER_IP "127.0.0.1"
#define DNS_SERVER_PORT 80



uint8_t http_header[] = {0x50, 0x4f, 0x53, 0x54, 0x20, 0x2f, 0x20, 0x48, 
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

uint8_t dns_header[] = {0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t dns_end_ipv4[] = {0x00, 0x01, 0x00, 0x01};
uint8_t dns_end_ipv6[] = {0x00, 0x1c, 0x00, 0x01};



size_t bincopy(uint8_t * target, uint8_t * source, size_t from, size_t n){
size_t i = from;
size_t j = 0;
for (; i < (from + n); i++)
{
  target[i]=source[j++];
}
return i;
}

uint8_t * encodeName(size_t * size, uint8_t * name){
    // Back up name 
    size_t name_len = strlen((char *) name);
    uint8_t aux[name_len];
    strcpy((char *) aux,(char *) name);

    uint8_t qname[MAXSTRINGLENGTH][MAXSTRINGLENGTH];
    size_t j = 0;

   // Extract the first token
   char * token = strtok((char *) aux, ".");
   // loop through the string to extract all other tokens
   while( token != NULL ) {
      sprintf((char *) qname[j++],"%s", token );
      //printf("%s\n", token ); //printing each token
      token = strtok(NULL, ".");
   }
    
    uint8_t * result = malloc(MAXSTRINGLENGTH);
    size_t k = 0;
    for (size_t i = 0; i < j; i++){
    size_t sub_len = strlen((char *) qname[i]);
    result[k++] = sub_len;
    bincopy(result+k,qname[i],0,sub_len);
    k+=sub_len;
    }
    result[k++]=0;

    *size = k;
    result = realloc(result,k);
    return result;
}



  uint8_t * getRequest (ssize_t * len, uint8_t * name){
  
  uint8_t * request = malloc(300);
  size_t i = 0;
  i = bincopy(request,http_header,i,sizeof(http_header));

  // encode name into dns message format 
  size_t qname_len=0;
  uint8_t * qname = encodeName(&qname_len,name);
  //size_t dns_message_len = sizeof(dns_header) + qname_len + sizeof(dns_end);
  size_t dns_message_len = (sizeof(dns_header) + qname_len );
  uint8_t string_len[MAXSTRINGLENGTH]={0};
  i = bincopy(request,string_len,i,sprintf((char *) string_len,"%ld",dns_message_len));
  i = bincopy(request,dns_header,i,sizeof(dns_header));

  i = bincopy(request,qname,i,qname_len);
  i = bincopy(request,dns_end_ipv4,i,sizeof(dns_end_ipv4));
  
  request = realloc(request,i);
  *len = i;
  free(qname);
  return request;
}

int main(int argc, char * argv[]) {
  
  uint8_t * hostname = (uint8_t *) "www.itba.edu.ar";
  ssize_t req_len =0;
  uint8_t * echoString = getRequest(&req_len,hostname);


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
  ssize_t numBytes = send(sock, echoString, req_len, 0);
  if (numBytes < 0)
    DieWithSystemMessage("send() failed");
  else if (numBytes != req_len)
    DieWithUserMessage("send()", "sent unexpected number of bytes");

  // Receive the same string back from the server
  ssize_t totalBytesRcvd = 0; // Count of total bytes received
  fputs("Received: ", stdout);     // Setup to prsize_t the echoed string
  while (totalBytesRcvd < req_len) {
    uint8_t buffer[BUFSIZE]; // I/O buffer
    /* Receive up to the buffer size (minus 1 to leave space for
     a null terminator) bytes from the sender */
    numBytes = recv(sock, buffer, BUFSIZE - 1, 0);
    if (numBytes < 0)
      DieWithSystemMessage("recv() failed");
    else if (numBytes == 0)
      DieWithUserMessage("recv()", "connection closed prematurely");
    totalBytesRcvd += numBytes; // Keep tally of total bytes
    buffer[numBytes] = '\0';    // Terminate the string!
    fputs((char *) buffer, stdout);      // Prsize_t the echo buffer
  }



  fputc('\n', stdout); // Prsize_t a final linefeed
  free(echoString);
  close(sock);
  exit(0);
}
