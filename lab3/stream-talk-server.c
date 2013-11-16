/*
 * @authors	Jon Hourany, Jacob Young
 * @date	09/17/13
 * @file	stream-talk-server.c
 *  
 * 
 * This code is an updated version of the sample code from "Computer Networks: A Systems
 * Approach," 5th Edition by Larry L. Peterson and Bruce S. Davis. Some code comes from
 * man pages, mostly getaddrinfo(3). 
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define SERVER_PORT "5432"
#define MAX_LINE 256
#define MAX_PENDING 5

int
main(int argc, char *argv[])
{
	struct addrinfo hints;
	struct addrinfo *rp, *result;
	struct timeval tv;
	char buf[MAX_LINE];
	int s, new_s;
	int len;
	fd_set rfds;
	int retval;
	int quit = 0;
	
	

	/* Build address data structure */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

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
	
	FD_ZERO(&rfds);
	FD_SET(s, &rfds);
	
	/* Wait for connection, then receive and print text */
	while(quit != 1)
	{
		tv.tv_sec  = 5;
		tv.tv_usec = 0;

		retval = select(s+1, &rfds, NULL, NULL, &tv);
		// If true
		if (retval == -1)
		{
		    perror("stream-talk-server: select failed with -1");
		    close(s);
		    exit(1);
		}
		else if (retval == 0)
		{
		     printf("stream-talk-server: select timed out \n");
		     quit = 1;
		}
		else
		{
		      if ((new_s = accept(s, rp->ai_addr, &(rp->ai_addrlen))) < 0)
		      {
			      perror("stream-talk-server: accept");
			      close(s);
			      exit(1);
		      }
		      while ((len = recv(new_s, buf, sizeof(buf), 0)))
		      {
			      fputs(buf, stdout);
		      }
		}
		
		close(new_s);
	}

	freeaddrinfo(result);
	close(s);

	return 0;
}
