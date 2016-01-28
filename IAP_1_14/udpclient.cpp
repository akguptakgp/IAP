#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <string>
#include <iostream>
#include <ifaddrs.h>
#include <time.h> 

using namespace std;
#define BUFFER_SIZE 100
char *UDP_SERVER_ADDR;
int portno;
int main(int argc, char *argv[])
{
	if(argc==3)
	{
		UDP_SERVER_ADDR=strdup(argv[1]);
		portno=atoi(argv[2]);
	}
	else
	{
		printf("Please specify UDP server address and port number\n");
		exit(0);
	}

	// declare the fis server struct so that connect can populate this
	struct sockaddr_in UDPServer_addr;
    socklen_t UDP_len = sizeof(UDPServer_addr);

 	memset(&UDPServer_addr,'\0',UDP_len);
 	UDPServer_addr.sin_family=AF_INET;
 	UDPServer_addr.sin_port=htons(portno);

 	inet_pton(AF_INET,UDP_SERVER_ADDR, &(UDPServer_addr.sin_addr));

	// udp socket file descriptor
	int sockfd_UDP;
	if ((sockfd_UDP = socket(AF_INET, SOCK_DGRAM,0)) == -1){perror("peerclient socket"); exit(0);}
	
	int n;
	char *buffer=new char[BUFFER_SIZE]; 
    time_t start,end;
    double seconds;
    time(&start);  /* get current time; same as: timer = time(NULL)  */
    while(1)
    {
    	while(1){
    		// printf("Waiting for Timeout\n");
    		time(&end);
    	if(difftime(end,start)>=10) { start=end; break;	}
    	}
    	memset(buffer,'\0',BUFFER_SIZE);
			sprintf(buffer,"ECHO REQUEST");
			printf("Sending ECHO REQUEST\n");
			
    		n=sendto(sockfd_UDP,buffer,strlen(buffer),0,(struct sockaddr*)&UDPServer_addr,UDP_len);
			printf("ECHO REQUEST Sent\n");
		 	struct sockaddr_in sender_addr;
			socklen_t sender_len = sizeof(sender_addr);
			memset(buffer,'\0',BUFFER_SIZE);
		    n= recvfrom(sockfd_UDP,buffer,BUFFER_SIZE-1,0,(struct sockaddr*)&sender_addr,&sender_len);
			if (n < 0) perror("ERROR reading from socket");
			else
			{	
				printf("ECHO REPLY Received\n");
			}
	}

close(sockfd_UDP);
return 0; 
}	