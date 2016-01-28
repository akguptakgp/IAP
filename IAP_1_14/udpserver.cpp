#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <csignal>
#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>

#define BUFFER_SIZE 100
int sockfd ;
void exithandler(int param)
{
	printf("UDP server Going Down......\n");
	close(sockfd);
	exit(0);
}

int main(int argc, char *argv[])
{
	signal(SIGINT,exithandler);
 	char ipstr[INET_ADDRSTRLEN];
     
    int portno;
 	if(argc==3)
	{
		// UDP_SERVER_ADDR=strdup(argv[1]);
		portno=atoi(argv[2]);
	}
	else
	{
		printf("Please specify UDP server address and port number\n");
		exit(0);
	}

	struct sockaddr_in serveraddr; /* server's addr */


 	bzero((char *) &serveraddr, sizeof(serveraddr));
  	serveraddr.sin_family = AF_INET;
  	// serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
  	inet_pton(AF_INET,argv[1], &(serveraddr.sin_addr));
  	serveraddr.sin_port = htons((unsigned short)portno);
    

    if ((sockfd =socket(AF_INET, SOCK_DGRAM,0)) == -1) {perror("listener: socket");}
    if (bind(sockfd,(struct sockaddr*)&serveraddr,sizeof(struct sockaddr_in)) == -1)
   	{close(sockfd);perror("listener: bind");}	
	memset(ipstr,'\0',INET_ADDRSTRLEN);
 	inet_ntop(AF_INET,&(serveraddr.sin_addr),ipstr,INET_ADDRSTRLEN);
   	printf("UDP SERVER up on %s::%d and waiting for clients to join...\n",ipstr,ntohs(serveraddr.sin_port));

    while(1)
    {
	    char buffer[BUFFER_SIZE]; 
	    memset(buffer,'\0',BUFFER_SIZE);

	    // used for storing client address while receiving
	  	struct sockaddr_in cli_addr;
    	socklen_t clilen = sizeof(cli_addr);

	   int  n= recvfrom(sockfd,buffer,BUFFER_SIZE-1,0,(struct sockaddr*)&cli_addr,&clilen);
	    
	    
	    inet_ntop(AF_INET,&cli_addr.sin_addr,ipstr,INET_ADDRSTRLEN);
	    if (n < 0) perror("ERROR reading from socket");

	 	printf("ECHO REQUEST from client %s::%d\n",ipstr,ntohs(cli_addr.sin_port));
	 	printf("Sending ECHO REPLY\n");

	 	memset(buffer,'\0',BUFFER_SIZE);
	 	sprintf(buffer,"ECHO REPLY");
	 	
		n=sendto(sockfd,buffer,strlen(buffer),0,(struct sockaddr*)&cli_addr,clilen);
		if(n>0) printf("ECHO REPLY SENT\n");
	}
	close(sockfd);

    return 0; 
}	
