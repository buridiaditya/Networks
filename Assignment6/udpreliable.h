void inttostr(char* array,int index,int value){
    /*
    array[index] = (value >> 24) & 0xFF;
    array[index+1] = (value>>16) & 0xFF;
    array[index+2] = (value>>8) & 0xFF;
    array[index+3] = value & 0xFF;
    */
    int* a = (int*)&array[index];
    *a = value;
    return;
}

int strtoint(char* array,int index){
    /*
    int a = array[index];
    int b = array[index+1];
    int c = array[index+2];
    int d = array[index+3];
    return a<<24 + b<<16 + c<<8 + d ;
    */
    int* a = (int*)&array[index];
    return *a;
}

_Bool checkACK(char* m,char* ack){
    return (m[0]^ack[0])|(m[1]^ack[1])|(m[2]^ack[2])|(m[3]^ack[3]);
}

void createACK(char* ack,char* buf){
    ack[0] = buf[0];
    ack[1] = buf[1];
    ack[2] = buf[2];
    ack[3] = buf[3];
    return;
}

void sendReliableUDP(int sockfd, char* buf,struct sockaddr_in serveraddr){
    int n;
    char recvbuf[ACKSIZE];
    while(1){
        //printf("Sending %s\n",buf+8);
        n = sendto(sockfd, buf, BUFSIZE,0,(struct sockaddr *)&serveraddr,sizeof(serveraddr));
        if (n < 0) 
            error("ERROR writing to socket");
        bzero(recvbuf,ACKSIZE);
        n = recvfrom(sockfd, recvbuf, ACKSIZE,0,(struct sockaddr *)&serveraddr,(socklen_t*)sizeof(serveraddr));
        //if (n < 0){ 
        //    error("ERROR receiving from socket");
        //}
        //else{
            if(checkACK(buf,recvbuf) == 0)
                break;
            else

                printf("Packet Retransmission\n");
       // }
    }
    bzero(buf,BUFSIZE);
    //strcpy(buf,recvbuf);
    return;
}

void recvReliableUDP(int sockfd, char* buf, struct sockaddr_in* serveraddr){
    int n,serverlen = sizeof(*serveraddr);
    char ack[ACKSIZE];
    n = recvfrom(sockfd,buf,BUFSIZE,0,(struct sockaddr*)serveraddr,&serverlen);
    if(n < 0)
        error("Error reading from the socket");
    //printf("Received %s\n",buf+8);
    bzero(ack,ACKSIZE);
    createACK(ack,buf);
   // printf("Sending ACK\n");
    n = sendto(sockfd,ack,ACKSIZE,0,(struct sockaddr*)serveraddr,serverlen);
    if(n<0)
        error("ERROR writing in server");
}
    

void setSequenceNumber(char* buf,int* index){
    inttostr(buf,0,*index);
    *index = *index+1;
}

void setMessageSize(char* buf,int size){
    inttostr(buf,4,size);
}
