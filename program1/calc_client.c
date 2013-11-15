/****************************************************************************
 * @author	Jon Hourany
 * @date	09/09/13
 * @class	EECE 555
 * @file	calc_client.c
 *
 * @breif	This program sends mathmatical expressions to a server for evaluation
 *
 * @long  
 *	This code is an updated version of the sample code from "Computer Networks:
 *	A Systems Approach," 5th Edition by Larry L. Peterson and Bruce S. Davis. 
 *	Some code comes from man pages, mostly getaddrinfo(3). 
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#define SERVER_PORT "5432"
#define MAX_LINE 2000
#define MAX_RECV 20

int
main(int argc, char *argv[])
{
	struct addrinfo hints;
	struct addrinfo *rp, *result;
	char *host;
	char buf      [MAX_LINE];
	char recv_buf [MAX_RECV];
	int s;
	int len;

	if (argc==3)
	{
		host = argv[1];
	}
	else
	{
		fprintf(stderr, "usage: %s host port\n", argv[0]);
		exit(1);
	}

	/* Translate host name into peer's IP address */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	if ((s = getaddrinfo(host, argv[2], &hints, &result)) != 0 )
	{
		fprintf(stderr, "%s: getaddrinfo: %s\n", argv[0], gai_strerror(s));
		exit(1);
	}

	/* Iterate through the address list and try to connect */
	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		if ((s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1 )
		{
			continue;
		}

		if (connect(s, rp->ai_addr, rp->ai_addrlen) != -1)
		{
			break;
		}

		close(s);
	}
	if (rp == NULL)
	{
		perror("stream-talk-client: connect");
		exit(1);
	}
	freeaddrinfo(result);

	/* Main loop: get and send lines of text */
	
	printf("Give me something to send!\n");

	while (fgets(buf, sizeof(buf), stdin))
	{
		if (strlen(buf) < 2) { break;} 		//On carrage return, break
		buf[MAX_LINE-1] = '\0';
		len = strlen(buf) + 1;
		send(s, (void *) &buf, len, 	      0);
		recv(s, (void *) &recv_buf, MAX_RECV, 0);
		printf("Answer: %s\n\n", recv_buf);
		printf("Give me moar math!\n");	
	}

	close(s);

	return 0;
}
