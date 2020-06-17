#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "Practical.h"
#include <time.h>
#include "http_response_parser.h"
#include "doh.h"


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

#define DNS_END_LEN 4
uint8_t dns_end_ipv4[] = {0x00, 0x01, 0x00, 0x01};
uint8_t dns_end_ipv6[] = {0x00, 0x1c, 0x00, 0x01};

uint8_t buffer[BUFSIZE];


// funciones locales
static size_t bincopy(uint8_t * target, uint8_t * source, size_t from, size_t n){
size_t i = from;
size_t j = 0;
for (; i < (from + n); i++)
{
  target[i]=source[j++];
}
return i;
}

static uint8_t checkResponse(uint8_t * response, ssize_t len){
   
  for (ssize_t i = 0; i < len; i++)
  {
    printf("%c - 0x%x \n", response[i],response[i]);
  }

  return 0;
}

static uint8_t * encodeName(size_t * size, uint8_t * name){
    // Back up name 
    size_t name_len = strlen((char *) name);
    uint8_t aux[name_len + 1];
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



static uint8_t * getRequest (ssize_t * len, uint8_t * name, uint8_t * dns_end_ver){
  
  uint8_t * request = malloc(300);
  size_t i = 0;
  i = bincopy(request,http_header,i,sizeof(http_header));

  // encode name into dns message format 
  size_t qname_len=0;
  uint8_t * qname = encodeName(&qname_len,name);
  //size_t dns_message_len = sizeof(dns_header) + qname_len
  size_t dns_message_len = (sizeof(dns_header) + qname_len );
  uint8_t string_len[MAXSTRINGLENGTH]={0};
  i = bincopy(request,string_len,i,sprintf((char *) string_len,"%ld",dns_message_len));
  i = bincopy(request,dns_header,i,sizeof(dns_header));

  i = bincopy(request,qname,i,qname_len);
  i = bincopy(request,dns_end_ver,i,DNS_END_LEN);
  
  request = realloc(request,i);
  *len = i;
  free(qname);
  return request;
}

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



// INTERFACE
struct http_response * getIpbyName(uint8_t * hostname) {
  
// I/O buffer

  // Type A Query

  ssize_t req_len =0;
  uint8_t * query;
  
  query = getRequest(&req_len,hostname,dns_end_ipv4);
  ssize_t totalBytesRcvd = 0; 
  totalBytesRcvd =  send_query(query, req_len);
  

  
  struct http_response * myentry = http_response_parser(buffer,(size_t) totalBytesRcvd);
  
  for (ssize_t i = 0; i < totalBytesRcvd; i++)
  {
    printf("0x%x\n",buffer[i]);
  }
  printf("bytes: %d\n",totalBytesRcvd);


  free(query);
  return myentry;
}

int main(){

  struct http_response * myentry = getIpbyName("cloudflare.com");
  
  
  printf("code: %d\n", myentry->status_code);
  printf("ipv4qty: %d\n", myentry->ipv4_qty);

  for (size_t i = 0; i < myentry->ipv4_qty ; i++)
  {
    for (size_t k = 0; k < IP_4_BYTES; k++)
    {
    printf("%d.",myentry->ipv4_addr[i].byte[k]);
    }
   printf("\n"); 
  }
  printf("ipv6qty: %d\n", myentry->ipv6_qty);


  
  free(myentry);

  return 0;
}
