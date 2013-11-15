/*
 * @author	Jon Hourany
 * @file	packets.c
 * @date	10/23/13
 *
 * @class	EECE 555
 * @assignment	Program 3
 *
 * @brief	A watered down wireshark program
 *
 * Some code used from/inspired by tutorial at www.tcpdum.org/pcap.html
 */

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET   14
#define IPV4		2048
#define IPV6		34525
#define ARP		2054
#define VLAN		33024

/* Ethernet header */
struct ethernet_header {
	u_char ether_dhost[ETHER_ADDR_LEN]; 	/* Destination host address 	*/
	u_char ether_shost[ETHER_ADDR_LEN]; 	/* Source host address		*/
	u_short ether_type;			/* IP? ARP? RARP? etc 		*/
};

/* VLAN header */
struct vlan_header {
	u_char tag_id[2];	/* VLAN Tag protocol ID 		*/
	u_char tag_cntrl[2];	/* VLAN Tag control information 	*/
#define VLAN_ID_MASK 0x0fff	/* VLAN ID Mask (AND w/ tag cntrl)	*/
};
#define VLAN_ID_H (((vlan)->tag_cntrl[0]) & 0x0f) /* Clears upper non-id bits 	*/
#define VLAN_ID_L ((vlan)->tag_cntrl[1])	  /* Lower 8-bits are part of ID*/

/* IP header */
struct ip_header {
	u_char ip_vhl;		/* version << 4 | header length >> 2 	*/
	u_char ip_tos;		/* type of service 			*/
	u_short ip_len;		/* total length 			*/
	u_short ip_id;		/* identification 			*/
	u_short ip_off;		/* fragment offset field 		*/
#define IP_RF 0x8000		/* reserved fragment flag 		*/
#define IP_DF 0x4000		/* dont fragment flag 			*/
#define IP_MF 0x2000		/* more fragments flag 			*/
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits 		*/
	u_char ip_ttl;		/* time to live 			*/
	u_char ip_p;		/* protocol 				*/
	u_short ip_sum;		/* checksum 				*/
	struct in_addr* ip_src,ip_dst;    /* source and dest address 	*/
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* ARP header */
struct arp_header {
	u_char hwd_type		[2];
	u_char protocol_type	[2];
	u_char len		[2];
	u_char opcode		[2];
	u_char src_addr		[6];
	u_char src_ip		[6];
	u_char dst_ip       	[6];
	u_char dst_protocol   	[6];
};
	
/* TCP header */
typedef u_int tcp_seq;

struct tcp_header {
	u_short th_sport;	/* source port 			*/
	u_short th_dport;	/* destination port 		*/
	tcp_seq th_seq;		/* sequence number 		*/
	tcp_seq th_ack;		/* acknowledgement number 	*/
	u_char th_offx2;	/* data offset, rsvd 		*/
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window 		*/
	u_short th_sum;		/* checksum 		*/
	u_short th_urp;		/* urgent pointer 	*/
};

int main(int argc, char *argv[]) {

	char pcap_buff[PCAP_ERRBUF_SIZE];       /* Error buffer used by pcap functions 	*/
	char src_addr_buff[INET6_ADDRSTRLEN];	/* Buffer for inet_pton 		*/
	char dst_addr_buff[INET6_ADDRSTRLEN];	/* Buffer for inet_pton 		*/
	pcap_t *pcap_handle = NULL;             /* Handle for PCAP library 		*/
	struct pcap_pkthdr *packet_hdr = NULL;  /* Packet header from PCAP		*/
	const u_char *packet = NULL;	        /* Packet data from PCAP 		*/
	int ret = 0;                            /* Return value from library calls 	*/
	u_short ntohs_ether_type;		/* Net to Host EtherType conversion	*/
	char *trace_file = NULL;                /* Trace file to process 		*/
	char *dev_name = NULL;                  /* Device name for live capture 	*/
	char use_file = 0;                      /* Flag to use file or live capture 	*/
	const struct ethernet_header *ethernet; /* The ethernet header 			*/
	const struct ip_header  *ip;		/* The IP header 			*/
	const struct arp_header *arp;		/* The ARP header			*/
	const struct vlan_header *vlan;		/* The VLAN header			*/
	//const char *payload; 			/* Packet payload 			*/

	/* The following vars have no use in this program, but may be useful later on */
	//u_int size_ip;
	//u_int size_tcp;
	/* Check command line arguments */
	if( argc > 2 ) {
		fprintf(stderr, "Usage: %s trace_file\n", argv[0]);
		return -1;
	}
	else if( argc > 1 ){
		use_file = 1;
		trace_file = argv[1];
	}
	else {
		use_file = 0;
	}

	/* Open the trace file, if appropriate */
	if( use_file ){
		pcap_handle = pcap_open_offline(trace_file, pcap_buff);
		if( pcap_handle == NULL ){
			fprintf(stderr, "Error opening trace file \"%s\": %s\n", trace_file, pcap_buff);
			return -1;
		}
		printf("Processing file '%s'\n", trace_file);
	}
	/* Lookup and open the default device if trace file not used */
	else{
		dev_name = pcap_lookupdev(pcap_buff);
		if( dev_name == NULL ){
			fprintf(stderr, "Error finding default capture device: %s\n", pcap_buff);
			return -1;
		}
		pcap_handle = pcap_open_live(dev_name, BUFSIZ, 1, 0, pcap_buff);
		if( pcap_handle == NULL ){
			fprintf(stderr, "Error opening capture device %s: %s\n", dev_name, pcap_buff);
			return -1;
		}
		printf("Capturing on interface '%s'\n", dev_name);
	}

	/* Populate packet and setup structs */
	ret	 = pcap_next_ex(pcap_handle, &packet_hdr, &packet);
	ethernet = (struct ethernet_header*)(packet);
	ip	 = (struct ip_header*)(packet + SIZE_ETHERNET);
	arp	 = (struct arp_header*)(packet + SIZE_ETHERNET);
	vlan	 = (struct vlan_header*)(packet + SIZE_ETHERNET-2); //Moves pointer up to EtherType

	/* The following code block has no function in this program, but may be useful later on */
	/*size_ip = IP_HL(ip)*4;

	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
	}
	tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;

	if (size_tcp < 20) 
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
	}*/
	//payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* Loop through all the packets in the trace file.
	 * ret will equal -2 when the trace file ends.
	 * This is an infinite loop for live captures. */
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
			int i = 0;
			ntohs_ether_type = ntohs(ethernet->ether_type);
			
			for(i; i < 6; i++) {
				printf("%02X", ethernet->ether_shost[i]);
				if (i % 1 == 0 && i != 5) { printf(":"); }
			}
			i = 0;
			
			printf(" -> ");

			for(i; i < 6; i++) {
				printf("%02X", ethernet->ether_dhost[i]);
				if (i % 1 == 0 && i != 5) { printf(":"); }
			}
			i = 0;
			switch (ntohs_ether_type)
			{
				case(IPV4):
					printf(" [IPv4] ");
					inet_ntop(AF_INET, &(ip->ip_src), src_addr_buff, INET_ADDRSTRLEN);
					inet_ntop(AF_INET, &(ip->ip_dst), dst_addr_buff, INET_ADDRSTRLEN);
					printf("%s -> %s", src_addr_buff, dst_addr_buff);
				break;
				case(IPV6):
					printf(" [IPv6] ");
					inet_ntop(AF_INET6, &(ip->ip_src), src_addr_buff, INET6_ADDRSTRLEN);
					inet_ntop(AF_INET6, &(ip->ip_dst), dst_addr_buff, INET6_ADDRSTRLEN);
					printf("%s -> %s", src_addr_buff, dst_addr_buff);
				break;
				case(ARP):
					inet_ntop(AF_INET, &(arp->src_ip), src_addr_buff, INET_ADDRSTRLEN);
					inet_ntop(AF_INET, &(arp->dst_ip), dst_addr_buff, INET_ADDRSTRLEN);
					printf(" [ARP] ");

					if (arp->opcode[1] == 1)
					{
						printf("%s requests %s", src_addr_buff, dst_addr_buff);
					}
					else if (arp->opcode[1] == 2)
					{
						int i = 0;

						printf(" %s at ", src_addr_buff);
						for(i; i < 6; i++) {
                                			printf("%02X", ethernet->ether_dhost[i]);
                                 			if (i % 1 == 0 && i != 5) { printf(":"); }
						
                         			}
                         			i = 0;
					}
				break;
				case(VLAN):
					printf(" [VLAN] ID = %i", VLAN_ID_H + VLAN_ID_L); 
				break;
				default:
					printf(" [Other] ");
				break;	
			}
			
			printf("\n");
		}

		/* Get the next packet */
		ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet);
	}

	/* Close the trace file or device */
	pcap_close(pcap_handle);
	return 0;
}
