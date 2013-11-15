/*
 * @author	Jon Hourany
 * @file	arp_resolver.c
 * @date	11/13/13
 *
 * @brief 	This program is to use pcap injection to create an ARP packet
 *
 */

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <sys/types.h>
#include <netinet/in.h>
#include <pcap/pcap.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET   14
#define IPV4		2048
#define IPV6		34525
#define ARP		2054
#define VLAN		33024
#define ETHERNET_HTYPE	0x1
#define	ETHERNET_HLEN	0x6
#define IPV4_PTYPE	0x0800
#define IPV4_PLEN	0x4
#define ARP_REQUEST	1

/* Ethernet header */
struct ethernet_header {
	u_char dhost[ETHER_ADDR_LEN]; 	/* Destination host address 	*/
	u_char shost[ETHER_ADDR_LEN]; 	/* Source host address		*/
	u_short type;			/* IP? ARP? RARP? etc 		*/
};

/* ARP header */
struct arp_header {
	u_short hwd_type;
	u_short protocol_type;
	u_char len		[2];
	u_short opcode;
	u_char src_addr		[6];
	u_char src_ip		[4];	
	u_char dst_addr		[6];
	u_char dst_ip		[4];
};

int main(int argc, char *argv[]) {

	/* Variables for pcap packet parsing */
	char pcap_buff[PCAP_ERRBUF_SIZE];       /* Error buffer used by pcap functions */
	pcap_t *pcap_handle = NULL;             /* Handle for PCAP library */
	struct pcap_pkthdr *packet_hdr = NULL;  /* Packet header from PCAP */
	const u_char *packet_data = NULL;       /* Packet data from PCAP */
	int ret = 0;                            /* Return value from library calls */
	char *dev_name = NULL;                  /* Device name for live capture */

	/* Variables for getifaddrs */
	struct sockaddr_ll *af_pkt;
    	struct ifaddrs *ifaddr, *ifa;
    	int family, s;
    	char host[NI_MAXHOST];
    	unsigned char *pname;
	
	/* General program variables */	
	struct arp_header outgoing_arp;			/* Outgoing Arp Header	*/
	const struct arp_header *incoming_arp;  	/* Incoming Arp Header	*/
	struct ethernet_header outgoing_ethernet; 	/* Outgoing Ethernet Hdr*/
	const struct ethernet_header *incoming_ethernet;/* Incoming Ethernet Hdr*/
	char outgoing_buffer[1500];
	struct in_addr pton_host;
	struct in_addr pton_dest;
	uint32_t htonl_host;

	/* Check command line arguments */
	if( argc != 2 ) 
	{
		fprintf(stderr, "Usage: %s interface (eth0, wlan0,...)\n", argv[0]);
		return -1;
	}
	
	if (getifaddrs(&ifaddr) == -1)
	{
  		perror("getifaddrs");
 		exit(EXIT_FAILURE);
   	}

	/* Lookup and open the requested interface */
	dev_name = argv[1]; 

    	/* Walk through linked list, maintaining head pointer so we can free list later */
    	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
        	if (ifa->ifa_addr == NULL)
            		continue;

	        family = ifa->ifa_addr->sa_family;

		/* Pull MAC and IP from ifa struct and populate the respective fields in outgoing ARP Packet */
		if (strcmp(ifa->ifa_name, "wlan0") == 0)
	        {
	        	if (family == AF_INET)
			{
        		    	s = getnameinfo(ifa->ifa_addr,
        		        (family == AF_INET) ? sizeof(struct sockaddr_in) :
        		        sizeof(struct sockaddr_in6),
        		        host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        		    	if (s != 0) 
				{
        		        	printf("getnameinfo() failed: %s\n", gai_strerror(s));
        		        	exit(EXIT_FAILURE);
        		    	}
			}
		        else if (family == AF_PACKET) 
			{
		        	af_pkt = (struct sockaddr_ll *) ifa->ifa_addr;
		        	pname  = (unsigned char *) &(af_pkt->sll_addr);
			}
		}
		else
		{
		}
	}

	//inet_pton(AF_INET, "74.125.224.72", &pton_dest);
	inet_pton(AF_INET, "132.241.228.95", &pton_dest);

	/* If the interface exisists and the MAC/IP values are ready, populate outgoing_arp */
	outgoing_arp.hwd_type		= htons((uint16_t) ETHERNET_HTYPE);
	outgoing_arp.protocol_type	= htons((uint16_t) IPV4_PTYPE);
	outgoing_arp.len[0]		= ETHERNET_HLEN;
	outgoing_arp.len[1]		= IPV4_PLEN;
	outgoing_arp.opcode		= htons((uint16_t) ARP_REQUEST);
	memcpy(&outgoing_arp.src_addr, pname, 6);	
	memcpy(&outgoing_arp.src_ip, &(pton_host), 4);
	memset(&outgoing_arp.dst_addr, 0x00000000, 6);
	memcpy(&outgoing_arp.dst_ip, &(pton_dest), 4);//outgoing_arp.dst_ip = 0x4A7DE048 //htonl((uint32_t) 0x4A7DE048);

	memset(&outgoing_ethernet.dhost, 0xFFFFFFFF, 6); 
	memcpy(&outgoing_ethernet.shost, pname, 6);
	outgoing_ethernet.type = htons((uint16_t) ARP);
/*	printf("ETHERNET TEST: \n");	
				int i =0;
				for(i; i < 6; i++) 
				{
                                	printf("%02X", outgoing_ethernet.dhost[i]);
                                       	if (i != 5) { printf(":"); }	
				}
				i = 0;
	printf("\nEND TEST \n");
*/	pcap_handle = pcap_open_live(dev_name, BUFSIZ, 1, 0, pcap_buff);
	if( pcap_handle == NULL ){
		fprintf(stderr, "Error opening capture device %s: %s\n", dev_name, pcap_buff);
		return -1;
	}
	memcpy(&outgoing_buffer, &outgoing_ethernet, sizeof(struct ethernet_header));
	memcpy((char *) &outgoing_buffer+14, &outgoing_arp, sizeof(struct arp_header));
	pcap_inject(pcap_handle, &outgoing_buffer, sizeof(struct ethernet_header)+sizeof(struct arp_header));
	printf("Capturing on interface '%s'\n", dev_name);
	
	/* This is an infinite loop for live captures. */

	/* Align ARP Pointers */
	ret	 		= pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
	incoming_ethernet 	= (struct ethernet_header*)(packet_data);
	incoming_arp		= (struct arp_header*)(packet_data + SIZE_ETHERNET);

	while( ret != -2 ) {

		/* An error occurred */
		if( ret == -1 ) {
			pcap_perror(pcap_handle, "Error processing packet:");
			pcap_close(pcap_handle);
			return -1;
		}

		/* Unexpected return values; other values shouldn't happen when reading trace files */
		else if( ret != 1 ) {
			fprintf(stderr, "Unexpected return value (%i) from pcap_next_ex()\n", ret);
			pcap_close(pcap_handle);
			return -1;
		}

		/* Process the packet and print results */
		else {
			/*
			 *
			 * Put your code here
			 *
			 */

			/* Examples:
			 * Print the first byte of the packet
			 * printf("%02X", packet_data[0]);

			 * Print the fifth byte of the packet
			 * printf("%02X", packet_data[4]);
			 */
			
		}

		/* Get the next packet */
		ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
	}

	/* Close the trace file or device */
	pcap_close(pcap_handle);
	return 0;
}
