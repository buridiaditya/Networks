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
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>

#define SLEEP_VAL 1
#define BUFSIZE 1024
#define ACKSIZE 64
#define TIMEOUT 1
#define MAXBUFFER 2000
int WINDOW_SIZE = 3;
/*
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(0);
}

#include "../udpreliable.h"

static int alarm_status = 0;
void mysig(int sig){
    pid_t pid;
    printf("PARENT : Received signal %d \n", sig);
    if (sig == SIGALRM){
        alarm_status = 1;
    }
}
int main(int argc, char **argv) {
    int sockfd, portno, n,seq = 0,ack_no;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    int serverlen;
    char* filename;
    char** buf;
    char ack[ACKSIZE];
    FILE* file;
    char temp;
    char* size_in_string;
    char* no_of_chunks_str;
    MD5_CTX mdContext;
    unsigned char checksum[MD5_DIGEST_LENGTH+1];
    char* filename_size;
    struct stat st;
    int length_of_chunk;
    int no_of_chunks,i;
    struct timeval timeout;
    int base = 1, next_seq_no = 1,status,increment,CW=1;
    /* check command line arguments */
    if (argc != 4) {
        fprintf(stderr,"usage: %s <hostname> <port> <filename>\n", argv[0]);
        exit(0);
    }


    hostname = argv[1];
    portno = atoi(argv[2]);
    filename = argv[3];

    /* Install signal handler for SIGALRM */
    (void) signal(SIGALRM,mysig);

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

    /* Set Socket Properties - Non Blocking Socket*/
    //timeout.tv_sec = TIMEOUT;
    //timeout.tv_usec = 0;
    //setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,(const char*) &timeout,sizeof(timeout));
    //int status = fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);

    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
            (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portno);

    /*
     * Initalize Application layer buffer SIZE = WINDOW_SIZE * BUF_SIZE
     */
    buf = (char**) malloc(sizeof(char*)*MAXBUFFER);
    for(i = 0; i < MAXBUFFER; i++)
        buf[i] = (char*) malloc(sizeof(char)*BUFSIZE);

    /*
     * Send file name and size of file
     */
    length_of_chunk = 0;
    size_in_string = (char*) malloc(10);
    no_of_chunks_str = (char*) malloc(10);

    stat(filename,&st); // SIZE OF FILE
    no_of_chunks = ceil(st.st_size/(double)(BUFSIZE-8)); // NO OF CHUNKS INTO WHICH FILE IS DIVIDED

    /*
     * Create the HELLO Message containing filename, size of file, no of chunks
     */
    bzero(buf[0],BUFSIZE);
    strcpy(buf[0]+8,filename);
    sprintf(size_in_string,"%d",(int)st.st_size);
    strcat(buf[0]+8,":");
    strcat(buf[0]+8, size_in_string);
    strcat(buf[0]+8,":");
    sprintf(no_of_chunks_str,"%d",no_of_chunks);
    strcat(buf[0]+8, no_of_chunks_str);
    setSequenceNumber(buf[0],&seq);
    setMessageSize(buf[0],strlen(buf[0]));
    sendReliableUDP(sockfd,buf[0],serveraddr);

    file = fopen(filename,"r");

    //int status = fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);
    MD5_Init(&mdContext);
    bzero(buf[0],BUFSIZE);
    i = 0;
    ack_no = 0;
    printf("File will be sent in %d packets.\n",no_of_chunks);
    while(feof(file) == 0 || base != next_seq_no){
        if(next_seq_no - base < WINDOW_SIZE && next_seq_no <= no_of_chunks){

            /* Start Timer */
            if(base == next_seq_no)
                alarm(SLEEP_VAL);

            /* Read Packet */
            fread(buf[next_seq_no%MAXBUFFER]+8,BUFSIZE-8,1,file);

            /* Create Packet */
            setSequenceNumber(buf[next_seq_no%MAXBUFFER],&next_seq_no);
            setMessageSize(buf[next_seq_no%MAXBUFFER],strlen(buf[next_seq_no%MAXBUFFER]+8));

            /* Send data */
            n = sendto(sockfd,buf[next_seq_no%MAXBUFFER],BUFSIZE,0,(struct sockaddr*)&serveraddr,sizeof(serveraddr));
            if(n < 0)
                error("Error writing to socket");

            printf("Transmitting Packet %d\n",next_seq_no);

            /* Update Hash */
            MD5_Update(&mdContext,buf[next_seq_no%MAXBUFFER]+8,BUFSIZE-8);

            /* Increment next_seq_no */
            next_seq_no++;
            CW = next_seq_no;
            bzero(buf[next_seq_no%MAXBUFFER],BUFSIZE);
        }
        else{
            increment = 0;
            if(ack_no == no_of_chunks)
                break;
            do{
                if(ack_no == no_of_chunks)
                    break;
                bzero(ack,ACKSIZE);
                n = recvfrom(sockfd,ack,ACKSIZE,MSG_DONTWAIT,(struct sockaddr*)&serveraddr,(socklen_t*)&serverlen);
                if( n > 0 ){
                    ack_no = strtoint(ack,0);
                    printf("ACK of Packet %d received\n",ack_no);
                    if(ack_no >= base && ack_no < CW){
                        increment += ack_no - base + 1;
                        base = ack_no+1;
                        alarm(SLEEP_VAL);
                    }
                }
            }while(alarm_status == 0 && ack_no != no_of_chunks);
            alarm_status = 0;

            /* Retransmission if required */
            if(base != next_seq_no){
                alarm(SLEEP_VAL);
                int temp = CW;
                if(base != CW && base + WINDOW_SIZE/2 > next_seq_no)
                    temp = next_seq_no;
                else if(base == CW && base + WINDOW_SIZE*2 > next_seq_no){
                    temp = next_seq_no;
                }
                for(i = base; i < temp; i++){
                    n = sendto(sockfd,buf[i%MAXBUFFER],BUFSIZE,0,(struct sockaddr*)&serveraddr,sizeof(serveraddr));
                    if(n < 0)
                        error("Error writing to socket");
                    printf("Retransmitting Packet %d\n",i);
                }
                if(base != CW && WINDOW_SIZE != 1){
                  WINDOW_SIZE /= 2;
                }else{
                  if(WINDOW_SIZE *2 < MAXBUFFER)
                      WINDOW_SIZE *= 2;
                }
                CW = base + WINDOW_SIZE;
            }
            else if(WINDOW_SIZE *2 < MAXBUFFER){
                WINDOW_SIZE *= 2;
            }
        }
        //sendReliableUDP(sockfd,buf,serveraddr);
    }
    printf("\nFile sent in %d chunks.\n",no_of_chunks);

    MD5_Final(checksum,&mdContext);
    checksum[MD5_DIGEST_LENGTH] = '\0';
    //status = fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | ~O_NONBLOCK);


    /* print the server's reply */
    bzero(buf[0], BUFSIZE);
    recvReliableUDP(sockfd,buf[0],&serveraddr);
    printf("%s, %s\n",buf[0],checksum);
    if(strcmp(buf[0],checksum) == 0)
        printf("Check sum matched\n.");
    else
        printf("Check sum not matched\n.");
    close(sockfd);
    return 0;
}
