#define MAXBUFFER 1024
#include <stdio.h>
#include <pthread.h>
typedef struct TCP_Control_Block{
	int seq_no;
	int window_size;
	int recv_window;
	int congestion_window_size;
	int last_unack;
	int next_seq_no;
	int ssthresh;
	int expected_seq_no;
} TCP_Control_Block;

typedef struct buffer{
	char* buf;
	int size;
	int socket;
	struct sockaddr_in* address; 
	int seq;
} buffer;

typedef struct packet_h{
	char type;
	int ack_no;
	int seq_no;
	int window_size;
}

typedef struct buffer_list{
	buffer* list;
	int size;
}

buffer_list* sender_buf = NULL;
buffer_list* receiver_buf = NULL;
TCP_Control_Block* TCB = NULL;
pthread_t sender_t;
pthread_t receiver_t;

int accept_quik(int sockfd,struct sockaddr_in* addr, socklen_t* addrlen){
	char SYN[sizeof(packet_h)];
	char ACK[sizeof(packet_h)];
	char SYN_ACK[sizeof(packet_h)];
	int expected_seq_no,n;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setscope(&attr,PTHREAD_SCOPE_SYSTEM);


	n = recvfrom(socket,SYN,sizeof(packet_h),0,addr,addrlen);
	if(n < 0){
		fprintf(stderr,"Error receiving SYN packet\n");
		return -1;
	}
	
	create_tcp_header(SYN,SYN_ACK); // TODO
	init_tcp_state();

	sendto(socket,SYN_ACK,sizeof(packet_h),0,addr,*addrlen);
	if(n < 0){
		fprintf(stderr,"Error sending SYN-ACK packet\n");
		return -1;
	}

	n = recvfrom(socket,ACK,sizeof(packet_h),0,addr,addrlen);
	if(n < 0){
		fprintf(stderr,"Error receiving ACK packet\n");
		return -1;
	}
	
	parse_tcp_header(ACK,); // TODO
	
	if(checkACK(SYN_ACK,ACK)){ // TODO 
		fprintf(stderr, "ACK does not match. Couldn't establish connection\n");
		return -1;
	}
	
	n = pthread_create(&sender_t,&attr,recv_quik,(void *)NULL); // TODO
	if(n<0){
        fprintf(stderr, "Error creating thread for receive.\n");
        return -1;
	}

	n = pthread_create(&receiver_t,&attr,send_quik,(void *)NULL); // TODO
	if(n<0){
        fprintf(stderr, "Error creating thread for sender.\n");
        return -1;
	}

	return 1;
}

int connect_quik(int sockfd, struct sockaddr_in* addr,socklen_t* len){
	char SYN[sizeof(packet_h)];
	char ACK[sizeof(packet_h)];
	char SYN_ACK[sizeof(packet_h)];

	create_tcp_header(SYN); // TODO



}
