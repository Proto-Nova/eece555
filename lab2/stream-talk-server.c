/***************************************************************************************
 * @authors	Jacob Young, Jon Hourany
 * @date	09/10/13
 * @file	stream-talk-server.c
 * 
 * @brief	lab2
 * 
 * This code is an updated version of the sample code from "Computer Networks: A Systems
 * Approach," 5th Edition by Larry L. Peterson and Bruce S. Davis. Some code comes from
 * man pages, mostly getaddrinfo(3). 
 **************************************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SERVER_PORT "5432"
#define MAX_LINE 256
#define MAX_PENDING 5

int main(int argc, char *argv[])
{
	struct addrinfo hints;
	struct addrinfo *rp, *result;
	char buf[MAX_LINE];
	int s, new_s;
	int len;
	char *recv_file_name;
	int fd; // file descriptor for recv_file_name;

	/* Build address data structure */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	
	if(argc == 2)
	{
		recv_file_name = argv[1];
	}
	else
	{
		printf("Error: Wrong Arguments\n");
		exit(1);
	}

	/* Get local address info */
	if ((s = getaddrinfo(NULL, SERVER_PORT, &hints, &result)) != 0 )
	{
		fprintf(stderr, "%s: getaddrinfo: %s\n", argv[0], gai_strerror(s));
		exit(1);
	}

	/* Iterate through the address list and try to perform passive open */
	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		if ((s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1 )
		{
			continue;
		}

		if (!bind(s, rp->ai_addr, rp->ai_addrlen))
		{
			break;
		}

		close(s);
	}
	if (rp == NULL)
	{
		perror("stream-talk-server: bind");
		exit(1);
	}
	if (listen(s, MAX_PENDING) == -1)
	{
		perror("stream-talk-server: listen");
		close(s);
		exit(1);
	}

	/* Wait for connection, then receive and print text */
	if ((fd = open(recv_file_name, O_CREAT|O_WRONLY|O_TRUNC, S_IRWXU)) > 0)
	{

		if ((new_s = accept(s, rp->ai_addr, &(rp->ai_addrlen))) < 0)
		{
			perror("stream-talk-server: accept");
			close(s);
			close(fd);
			close(new_s);
			exit(1);
		}
		while ((len = recv(new_s, buf, sizeof(buf), 0)))
		{
			if (len == -1)
			{
			    perror("stream-talk-server: receive");
			    close(s);
			    close(fd);
			    close(new_s);
			    exit(1);
			}
			
			write(fd, buf, len);
		}
		close(new_s);
	}
	else
	{
		printf("\nError: Cannot open file\n");
		freeaddrinfo(result);
		close(s);
		exit(1);
	}
	
	printf("\nTransfter Complete...\nExiting\n");
	freeaddrinfo(result);
	close(s);
	close(fd);
	return 0;
}
