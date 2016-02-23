#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/in.h>
#include <netinet/ip.h>
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
	char sAddr[45];
	char dAddr[45];
	char sPort[45];
	char dport[45];
	char status[45];
	long start;
	long end;
	long duration;
	int stodpackets;
	int dtospackets;
	int packets;
	int stodbytes;
	int dtosbytes;
	int bytes;
};

#define MAXPACKETS 1000
struct tcphdr *tcph[MAXPACKETS];
struct iphdr *iph[MAXPACKETS];
struct timeval timestamps[MAXPACKETS];
int packetcounter = 0;
int main(int argc, char *argv[]){
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
	int i = 0;
	while((packet = pcap_next(pcap, &header))!=NULL&&packetcounter < 6){
		process_packet(packet, header.ts, header.caplen);
		printPackets(iph[packetcounter], tcph[packetcounter], timestamps[packetcounter]);
		packetcounter ++;

	}
	return 0;
}
void printPackets(struct ip *ip, struct tcphdr *tcp, struct timeval ts){
	int i = 0;
	//Deals with the tcp header and timestamp
	printf("TCP\nTimestamp:%s TCP src_port=%u dst_port=%u seq = %u\nack seq = %u flags = %d%d%d%d%d%d\nWindow = %d Checksum = %d Urg = %d" ,
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
void print_tcp_packet(const u_char buffer, int size){/*
	unsigned short iphdrlen;
     
    	struct iphdr *iph = (struct iphdr *)( buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
     
	struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
             
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	printf("sequence: %u\n", ntohs(tcph->seq));
	printf("Source Address: \n");
	printf("Destination Address: %u\n", ntohs(tcph->dest));
	printf("Status: \n");
	printf("Start time: \n");
	printf("End Time: \n");*/
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
