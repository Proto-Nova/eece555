/*
 * @authors	Jon Hourany, Jacob Young
 * @date	09/02/13
 * 
 * @file	local-addrs.c
 * 
 * @sources	getifaddrs (man page)
 *
 */

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <sys/types.h>
#include <netinet/in.h>

int main(int argc, char *argv[])
{
    struct sockaddr_ll *af_pkt;
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
    char interface[6] = "wlan0";
    unsigned char *pname;

    if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    exit(EXIT_FAILURE);
    }

    /* Walk through linked list, maintaining head pointer so we
    can free list later */

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        /* Display interface name and family (including symbolic
        form of the latter for the common families) */

	printf("\n");
	if (strcmp(ifa->ifa_name, &interface) == 0)
	{
	  printf("Interfaces Match!\n");
	}
	else
	{
	  printf("Interfaces do not Match\n");
	}
	printf("------------------------------\n");
        printf("%s\t%s\t",
                ifa->ifa_name,
                (family == AF_PACKET) ? " AF_PACKET" :
                (family == AF_INET) ?   " AF_INET" :
                (family == AF_INET6) ?  " AF_INET6" : "");


        /* For an AF_INET* interface address, display the address */

        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                (family == AF_INET) ? sizeof(struct sockaddr_in) :
                sizeof(struct sockaddr_in6),
                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            printf("%s\n", host);
        }
	else {
	    //packet = (struct sockaddr_ll *) ifa->ifa_addr;
	    //printf("%02x\n", (int)packet->sll_addr);
	af_pkt = (struct sockaddr_ll *) ifa->ifa_addr;
	pname = (unsigned char *) &(af_pkt->sll_addr); 
	int i;
	for(i = 0; i<6; i++)
	{
		if(i!= 0)
		{
			printf(":");
		}
		printf("%02x", *(pname + i));

	}

	printf("\n");
	
	}
    }

    freeifaddrs(ifaddr);
    exit(EXIT_SUCCESS);
}
