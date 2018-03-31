#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <strings.h>
#include <error.h>

#define BUFSIZE 44

unsigned short cksum(char* icmp_header, int len){
  long sum = 0;  /* assume 32 bit long, 16 bit short */

  while(len > 1){
    sum += *((unsigned short*) icmp_header);
    icmp_header += sizeof(unsigned short);
    if(sum & 0x80000000)   /* if high order bit set, fold */
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
  }

  if(len)       /* take care of left over byte */
    sum += (unsigned short) *(unsigned char *)icmp_header;

  while(sum>>16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum;
}

int main(int argn,char** argv){
  int sockfd, n;
  struct sockaddr_in addr;
  socklen_t addr_len;
  struct iphdr* ip_header;
  struct icmphdr* icmp_header;
  char buffer[BUFSIZE];
  char recvBuffer[BUFSIZE];
  struct timeval* start;
  char* hostname;
  char* mode;
  int mode_ = 0;
  struct hostent *server;
  int val = 1;

  hostname = argv[1];
  mode = argv[2];
  bzero(buffer,BUFSIZE);
  bzero(recvBuffer,BUFSIZE);

  server = gethostbyname(hostname);
  if (server == NULL) {
      fprintf(stderr,"ERROR, no such host as %s\n", hostname);
      exit(0);
  }
  bzero((char *) &addr, sizeof(addr));
  addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr, (char *)&addr.sin_addr.s_addr, server->h_length);

  ip_header = (struct iphdr*) buffer;
  icmp_header = (struct icmphdr*) (buffer + sizeof(struct iphdr));
  start = (struct timeval*) (buffer + sizeof(struct iphdr) + sizeof(struct icmphdr));

  //printf("%d %d %d\n",sizeof(ip_header),sizeof(icmp_header),sizeof(start));

  sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
  if (sockfd < 0)
      perror("ERROR opening socket");

  if(strcmp(mode, "IP") == 0){

    n = setsockopt(sockfd, IPPROTO_IP,IP_HDRINCL,(void*)&val,(socklen_t)sizeof(val));
    if (n < 0)
        perror("Unable to set socket options");

    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    // TOTAL LENGTH FILLED BY OS
    // ID FILLED BY OS
    //ip_header->frag_off = 0x4000;
    ip_header->ttl = 43;
    ip_header->protocol = 1;
    // CHECKSUM FILLED BY OS
    // SOURCE ADDR FILLED BY OS
    ip_header->daddr = inet_addr(hostname);

    mode_ = 1;

  }

  icmp_header->type = 8;
  icmp_header->code = 0;
  icmp_header->un.echo.sequence = 1;
  icmp_header->checksum = 0;
  gettimeofday(start,NULL);
  icmp_header->checksum = cksum((char*)icmp_header,sizeof(struct icmphdr)+sizeof(struct timeval));

  if(mode_){
    n = sendto(sockfd,buffer,BUFSIZE,0,(struct sockaddr*)&addr,(socklen_t)sizeof(addr));
  }
  else{
    n = sendto(sockfd,buffer + sizeof(struct iphdr),BUFSIZE - sizeof(struct iphdr),0,(struct sockaddr*)&addr,(socklen_t)sizeof(addr));
  }
  if(n < 0)
      perror("Error writing to socket");
  //printf("WAITING\n");
  n = recvfrom(sockfd,recvBuffer,BUFSIZE,0,(struct sockaddr*)&addr,&addr_len);
  if(n < 0)
      perror("Error reading from socket");
  //printf("%X\n%X\n",buffer,recvBuffer);

  return 0;
}
