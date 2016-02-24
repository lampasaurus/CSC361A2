#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <pcap.h>
//If source IP, source port, destination IP, destination port are all the same, it's part of the same connection

//Only get statistics from complete TCP connections
//https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut7.html
//http://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
//Skip the IP and ethernet headers

const char *timestamp_string(struct timeval ts);
void problem_pkt(struct timeval ts, const char *reason);
void too_short(struct timeval ts, const char *truncated_hdr);

struct connection {
	//int num;
	int init;
	char sAddr[INET_ADDRSTRLEN];
	char dAddr[INET_ADDRSTRLEN];
	uint16_t sPort;
	uint16_t dPort;
	char status[INET_ADDRSTRLEN];
	long start;
	long end;
	long duration;
	int stodpackets;
	int dtospackets;
	int packets;
	int stodbytes;
	int dtosbytes;
	int bytes;
	int S;
	int F;
};

#define MAXPACKETS 1000
struct tcphdr *tcph[MAXPACKETS];
struct iphdr *iph[MAXPACKETS];
struct timeval timestamps[MAXPACKETS];
struct connection connections[MAXPACKETS];
int packetcounter = 0;


int main(int argc, char *argv[]){
	int i;
	for(i = 0; i < MAXPACKETS; i++){
		connections[i].init = connections[i].packets = connections[i].stodpackets = connections[i].dtospackets = connections[i].stodbytes = connections[i].dtosbytes = connections[i].bytes = connections[i].S = connections[i].F = 0;
	}
	pcap_t *pcap;
	struct pcap_pkthdr header;
	char errbuf[PCAP_ERRBUF_SIZE];
   	u_char *packet;

	if (argc < 2) {
    		fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
    		return(-1);
  	}
	//Opens the dump file
	pcap = pcap_open_offline(argv[1], errbuf);
   	if (pcap == NULL) {
     		fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf);
     		return(-1);
   	}
	//Loops through the packets for processing
	while((packet = pcap_next(pcap, &header))!=NULL&&packetcounter < 6){
		process_packet(packet, header.ts, header.caplen);
		printPackets(iph[packetcounter], tcph[packetcounter], timestamps[packetcounter]);
		packetcounter ++;

	}

	for(i = 0; i < packetcounter; i++){
		compareconnection(timestamps[i],iph[i],tcph[i]);
	}
	return 0;
}

//For debugging, prints all the relevant information about the packet headers
void printPackets(struct ip *ip, struct tcphdr *tcp, struct timeval ts){
	int i = 0;
	//Deals with the tcp header and timestamp
	printf("TCP\nTimestamp:%s TCP src_port=%u dst_port=%u seq = %u\nack seq = %u flags = %d%d%d%d%d%d\nWindow = %d Checksum = %d Urg = %d\n" ,
	timestamp_string(ts),
	ntohs(tcp->source),
	ntohs(tcp->dest),
	ntohl(tcp->seq),
	ntohl(tcp->ack_seq),
	//(unsigned int)tcph->doff,(unsigned int)tcph->doff*4),
	(unsigned int)tcp->urg,
	(unsigned int)tcp->ack,
	(unsigned int)tcp->psh,
	(unsigned int)tcp->rst,
	(unsigned int)tcp->syn,
	(unsigned int)tcp->fin,
	ntohs(tcp->window),
	ntohs(tcp->check),
	tcp->urg_ptr);

	struct in_addr saddr = ip->ip_src;
	struct in_addr daddr = ip->ip_dst;
	char inadd[INET_ADDRSTRLEN];
	char dstadd[INET_ADDRSTRLEN];
	inet_ntop( AF_INET, &saddr, inadd, INET_ADDRSTRLEN );
	inet_ntop( AF_INET, &daddr, dstadd, INET_ADDRSTRLEN );
	printf("IP src = %s dst = %s\n\n", inadd, dstadd);
}	

//Take a full ethernet encapsulation and extracts the tcp and ip headers, saving them for further use
void process_packet(u_char *packet, struct timeval ts, u_int capture_len){
	struct ip *ip;
	struct tcphdr *tcp;
	unsigned int IP_header_length;
	//Cuts out the unwanted ethernet headers
	if(capture_len < sizeof(struct ether_header)){
		too_short(ts, "Ethernet header");
		return;	
	}
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);
	
	//Cuts out the unwanted IP header
	if (capture_len < sizeof(struct ip)){
		too_short(ts, "IP header");
		return;
	}
	ip = (struct ip*) packet;
	IP_header_length = ip->ip_hl * 4;
	if (capture_len < IP_header_length){ 
		too_short(ts, "IP header with options");
		return;
	}
	if (ip->ip_p != IPPROTO_TCP){
		problem_pkt(ts, "non-TCP packet");
		return;
}
	packet += IP_header_length;
	capture_len -= IP_header_length;

	//Checks that there is enough information left to be a TCP header
	if (capture_len < sizeof(struct tcphdr*)){
		too_short(ts, "TCP header");
		return;
	}
	//Creats the tcp packet header and adds it to the global packets list
	tcp = (struct tcphdr*) packet;
	tcph[packetcounter] = tcp;
	iph[packetcounter] = ip;
	timestamps[packetcounter] = ts;
	
}

//Takes a timeval, ip header, and tcp header to create a new connection data structure
//Stores the connection data structure in the global connection array
void createconnection(int i, struct timeval ts, struct ip *ip, struct tcphdr *tcp){
	struct in_addr saddr = ip->ip_src;
	struct in_addr daddr = ip->ip_dst;
	char srcadd[INET_ADDRSTRLEN];
	char dstadd[INET_ADDRSTRLEN];
	inet_ntop( AF_INET, &saddr, srcadd, INET_ADDRSTRLEN );
	inet_ntop( AF_INET, &daddr, dstadd, INET_ADDRSTRLEN );

	connections[i].init = 1;
	strcpy(connections[i].sAddr, srcadd);
	strcpy(connections[i].dAddr, dstadd);
	connections[i].sPort = ntohs(tcp->source);
	connections[i].dPort = ntohs(tcp->dest);
	/*connections[i].status;
	connections[i].start;
	connections[i].end;
	connections[i].duration;
	connections[i].stodpackets;
	connections[i].dtospackets;
	connections[i].packets;
	connections[i].stodbytes;
	connections[i].dtosbytes;
	connections[i].bytes;
	connections[i].S;
	connections[i].F;*/
}
//Checks if the packets are part of an existing connection
void compareconnection(struct timeval ts, struct ip *ip, struct tcphdr *tcp){
	int i;
	struct in_addr saddr = ip->ip_src;
	struct in_addr daddr = ip->ip_dst;
	char srcadd[INET_ADDRSTRLEN];
	char dstadd[INET_ADDRSTRLEN];
	inet_ntop( AF_INET, &saddr, srcadd, INET_ADDRSTRLEN );
	inet_ntop( AF_INET, &daddr, dstadd, INET_ADDRSTRLEN );
	
	for(i = 0; i < packetcounter; i++){
		if(connections[i].init == 0){
		//If we reach a un-initialized connection without finding a matching one,
		//create a new connection
			createconnection(i, ts, ip, tcp);
			break;
		}
	}
}
//Adds new packet information to an existing connection
void updateconnection(struct timeval ts, struct ip *ip, struct tcphdr *tcp, struct connection con){
}
//Prints the formatted output from the connection
void printconnection(struct connection c){
	printf("Connection sAddr = %s dAddr = %s sPort = %d dPort = %d\n", c.sAddr, c.dAddr, c.sPort, c.dPort);
}

const char *timestamp_string(struct timeval ts)
	{
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
	}

void problem_pkt(struct timeval ts, const char *reason)
	{
	fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
	}

void too_short(struct timeval ts, const char *truncated_hdr)
	{
	fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
		timestamp_string(ts), truncated_hdr);
	}
