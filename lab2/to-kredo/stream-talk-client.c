/****************************************************************************
 * @author	Jacob Young, Jon Hourany
 * @date	09/11/13
 * @class	EECE 555
 * @file	stream-talk-client.c
 *
 * @breif	lab2. This program sends file data across a socket
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>       

#define SERVER_PORT "5432"
#define MAX_LINE 100

int main(int argc, char *argv[])
{
	struct addrinfo hints;
	struct addrinfo *rp, *result;
	char *host;
	char buf      [MAX_LINE];
	int s;
	char *file_name;
	int file_desc;
	ssize_t bytes_read;
	ssize_t bytes_sent;
	char *send_buf;

	if (argc==3)
	{
		host = argv[1];
		file_name = argv[2];
	}
	else
	{
		fprintf(stderr, "usage: %s host file_name", argv[0]);
		exit(1);
	}

	/* Translate host name into peer's IP address */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	if ((s = getaddrinfo(host, SERVER_PORT, &hints, &result)) != 0 ) { 
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

	if ((file_desc = open((char *) file_name, 0)) == -1)
	{
		printf("File open fail\n");
		exit(1);
	}
	
	
	/* Main loop: get and send lines of text */
		
	while ( (bytes_read = read(file_desc, (void *) &buf, MAX_LINE)) != 0 )
	{
		send_buf = (char *) &buf;

		if (bytes_read == -1)
		{
			printf("File Read Error\n");
			exit(1);
		}

		do
		{
			if ( (bytes_sent = send(s, (void *) send_buf, bytes_read,0)) < 0 )
			{
				printf("File send fail\n");
				exit(1);
			}
			send_buf = send_buf + (int)bytes_sent;
			bytes_read = (int)(bytes_read - bytes_sent);

		}while(bytes_sent != bytes_read);
	}
	printf("File Transfer Complete\n");
	close(s);
	close(file_desc);

	return 0;
}
