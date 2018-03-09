/* 
 * tcpclient.c - A simple TCP client
 * usage: tcpclient <host> <port>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <openssl/md5.h>
#include <sys/stat.h>
#include <math.h>

#define BUFSIZE 1024
#define ACKSIZE 64
#define TIMEOUT 5
/* 
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(0);
}

#include "../udpreliable.h"

int main(int argc, char **argv) {
    int sockfd, portno, n,seq = 0;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    int serverlen;
    char* filename;
    char buf[BUFSIZE];
    FILE* file;
    char temp;
    char* size_in_string;
    char* no_of_chunks_str;
    MD5_CTX mdContext;
    unsigned char checksum[MD5_DIGEST_LENGTH+1];
    char* filename_size;
    struct stat st;
    int length_of_chunk;
    int no_of_chunks;
    struct timeval timeout;
    /* check command line arguments */
    if (argc != 4) {
        fprintf(stderr,"usage: %s <hostname> <port> <filename>\n", argv[0]);
        exit(0);
    }

    hostname = argv[1];
    portno = atoi(argv[2]);
    filename = argv[3];

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (sockfd < 0) 
        error("ERROR opening socket");

    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        exit(0);
    }
    
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;
    setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,(const char*) &timeout,sizeof(timeout));

    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
            (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portno);

    /* connect: create a connection with the server */
    //if (connect(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) 
    //    error("ERROR connecting");

    /* get message line from the user */
    // printf("Please enter msg: ");
    // bzero(buf, BUFSIZE);
    // fgets(buf, BUFSIZE, stdin);

    /*
     * Send file name and size of file
     */
    length_of_chunk = 0;
    size_in_string = (char*) malloc(10);
    no_of_chunks_str = (char*) malloc(10);
    
    stat(filename,&st);
    no_of_chunks = ceil(st.st_size/(double)(BUFSIZE-8));
    
    bzero(buf,BUFSIZE);
    //buf[8] = '\0';
    strcpy(buf+8,filename); 
    sprintf(size_in_string,"%d",(int)st.st_size);
    strcat(buf+8,":");
    strcat(buf+8, size_in_string);
    strcat(buf+8,":");
    sprintf(no_of_chunks_str,"%d",no_of_chunks);
    strcat(buf+8, no_of_chunks_str);
    setSequenceNumber(buf,&seq);
    setMessageSize(buf,strlen(buf));
    sendReliableUDP(sockfd,buf,serveraddr); 
    
    MD5_Init(&mdContext);
    file = fopen(filename,"r");
    int i = 0;
    bzero(buf,BUFSIZE);
    
    printf("File will be sent in %d packets.\n",no_of_chunks);
    while(feof(file) == 0){
        fread(buf+8,BUFSIZE-8,1,file);

        MD5_Update(&mdContext,buf+8,BUFSIZE-8);
        
        setSequenceNumber(buf,&seq);
        setMessageSize(buf,strlen(buf));
        sendReliableUDP(sockfd,buf,serveraddr);
        //printf("Sent packet %d\n",seq);        
        bzero(buf,BUFSIZE);
        i++;
    }
    printf("\nFile sent in %d chunks.\n",i);
     
    MD5_Final(checksum,&mdContext);
    checksum[MD5_DIGEST_LENGTH] = '\0';


    /* print the server's reply */
    bzero(buf, BUFSIZE);
    recvReliableUDP(sockfd,buf,&serveraddr);
    printf("%s, %s\n",buf,checksum);
    if(strcmp(buf,checksum) == 0)
        printf("Check sum matched\n.");
    else
        printf("Check sum not matched\n.");
    close(sockfd);
    return 0;
}
