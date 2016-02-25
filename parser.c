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
	int init;
	char sAddr[INET_ADDRSTRLEN];
	char dAddr[INET_ADDRSTRLEN];
	uint16_t sPort;
	uint16_t dPort;
	uint32_t seqnum;
	uint32_t acknum;
	unsigned long start;
	unsigned long end;
	float duration;
	int stodpackets;
	int dtospackets;
	int packets;
	int stodbytes;
	int dtosbytes;
	int bytes;
	int S;
	int F;
	int sendf;
	int dstf;
	int reset;
	int maxwin;
	int minwin;
	int totalwin;
	float meanwin;
};

#define MAXPACKETS 10000
struct tcphdr *tcph[MAXPACKETS];
struct ip *iph[MAXPACKETS];
struct timeval timestamps[MAXPACKETS];
struct connection connections[MAXPACKETS];
int packetcounter, ccounter;


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
	//Loops through the packets and process them into connections
	packetcounter = 0;
	while((packet = pcap_next(pcap, &header))!=NULL){
		process_packet(packetcounter, packet, header.ts, header.caplen);
		//printf("packetcounter = %d ", packetcounter);
		//printPackets(iph[packetcounter], tcph[packetcounter], timestamps[packetcounter]);
		compareconnection(timestamps[packetcounter],iph[packetcounter],tcph[packetcounter]);	
		packetcounter ++;
	}
	char *spacewaster = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";	
	
	//print part B of the output
	for(i = 0; i < ccounter; i++){
		printconnection(i, connections[i]);
	}
	
	//print part A of the output
	printf("Total number of connections: %d\n",ccounter); 
	//print part C of the output
	int complete = 0;
	int reset = 0;
	int ended = 0;
	for(i = 0; i < ccounter; i++){
		if(connections[i].S >= 1 && connections[i].F>=1) complete++;
		if(connections[i].reset == 1) reset++;
		if(connections[i].F<=1 && connections[i].reset != 1) ended++;
	}
	printf("\nTotal number of complete TCP connections: %d\n", complete);
	printf("Number of reset connections: %d\n", reset);
	printf("Number of TCP connections that were still open when the trace capture ended: %d\n\n", ended);
	//print part D of the output
	float mintime = -1.0;
	float totaltime = 0.0;
	float maxtime = 0.0;
	int minpackets = -1;
	int maxpackets = 0;
	int totalpackets = 0;
	int minwin = -1;
	int maxwin = 0;
	float totalwin = 0;
	for(i = 0; i < ccounter; i++){
		//printf("%f, ", connections[i].minwin);
		if(connections[i].S >= 1 && connections[i].F>=1){
			if(mintime < 0.0) mintime = connections[i].duration;
			if(mintime > connections[i].duration) mintime = connections[i].duration;
			if(maxtime < connections[i].duration) maxtime = connections[i].duration;
			totaltime += connections[i].duration;

			if(minpackets == -1) minpackets = connections[i].packets;
			if(minpackets > connections[i].packets) minpackets = connections[i].packets;
			if(maxpackets < connections[i].packets) maxpackets = connections[i].packets;
			totalpackets += connections[i].packets;
		
			if(minwin == -1) minwin = connections[i].minwin;
			if(minwin > connections[i].minwin) minwin = connections[i].minwin;
			if(maxwin < connections[i].maxwin) maxwin = connections[i].maxwin;
			totalwin += connections[i].meanwin;
		}	
	}
	printf("\nMinimum time duration: %f seconds\n", mintime/1000000);
	printf("Mean time duration: %f seconds\n", totaltime/(float)ccounter/1000000);
	printf("Maximum time duration: %f seconds\n\n", maxtime/1000000);

	
	printrtt();	
	
	printf("Minimum number of packets including both send/recieved: %d\n", minpackets);
	printf("Mean number of packets including both send/recieved: %f\n", (float)totalpackets/ccounter);
	printf("Maximum number of packets including both send/recieved: %d\n\n", maxpackets);
	
	printf("Minimum receive window size including both send/recieved: %d\n", minwin);
	printf("Mean recieve window size including both send/recieved: %f\n", (float)totalwin/ccounter);
	printf("Maximum recieve window sizes including both send/recieved: %d\n\n", maxwin);
	return 0;
}


void printrtt(){
	//look at all packets
	//if they have similar (diff < 10) syn/ack_syn, group them
	//find statistics from each group
	//print the statistics
	float minRTT, meanRTT, maxRTT = 0.0;
	printf("Minimum RTT values including both send/recieved: %f\n", minRTT);
	printf("Mean RTT values including both send/recieved: %f\n", meanRTT);
	printf("Maximum RTT values including both send/recieved: %f\n\n", maxRTT); 
	return;
}

//Take a full ethernet encapsulation and extracts the tcp and ip headers, saving them for further use
void process_packet(int n, u_char *packet, struct timeval ts, u_int capture_len){
	struct ip *iphdr;
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
	iphdr = (struct ip*) packet;
	IP_header_length = iphdr->ip_hl * 4;
	if (capture_len < IP_header_length){ 
		too_short(ts, "IP header with options");
		return;
	}
	if (iphdr->ip_p != IPPROTO_TCP){
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
	tcph[n] = tcp;	
	iph[n] = iphdr;
	timestamps[n] = ts;
}

//Takes a timeval, ip header, and tcp header to create a new connection data structure
//Stores the connection data structure in the global connection array
void createconnection(struct timeval ts, struct ip *ip, struct tcphdr *tcp){
	printf("Creating connection %d\n",ccounter);	
	//printPackets(ip, tcp, ts);
	struct in_addr saddr = ip->ip_src;
	struct in_addr daddr = ip->ip_dst;
	char srcAdd[INET_ADDRSTRLEN];
	char dstAdd[INET_ADDRSTRLEN];
	inet_ntop( AF_INET, &saddr, srcAdd, INET_ADDRSTRLEN );
	inet_ntop( AF_INET, &daddr, dstAdd, INET_ADDRSTRLEN );
	connections[ccounter].init = 1;
	strcpy(connections[ccounter].sAddr, srcAdd);
	strcpy(connections[ccounter].dAddr, dstAdd);
	connections[ccounter].sPort = ntohs(tcp->source);
	connections[ccounter].dPort = ntohs(tcp->dest);
	connections[ccounter].seqnum = ntohl(tcp->seq);
	connections[ccounter].acknum = ntohl(tcp->ack_seq);
	connections[ccounter].packets = 1;
	connections[ccounter].start = ts.tv_sec * 1000000L + ts.tv_usec;
	connections[ccounter].end = ts.tv_sec * 1000000L + ts.tv_usec;
	connections[ccounter].duration = 0.0;
	connections[ccounter].stodpackets = 1;
	connections[ccounter].dtospackets = 0;
	connections[ccounter].packets = 1;
	connections[ccounter].stodbytes = (unsigned int)tcp->doff*4;	
	connections[ccounter].dtosbytes = 0;
	connections[ccounter].bytes = (unsigned int)tcp->doff*4;
	connections[ccounter].S = (unsigned int)tcp->syn;
	connections[ccounter].F = (unsigned int)tcp->fin;
	connections[ccounter].reset = (unsigned int)tcp->rst;
	connections[ccounter].sendf = 0;
	connections[ccounter].dstf = 0;
	connections[ccounter].minwin = (int)ntohs(tcp->window);
	connections[ccounter].meanwin = (int)ntohs(tcp->window);
	connections[ccounter].maxwin = (int)ntohs(tcp->window);
	connections[ccounter].totalwin = (int)ntohs(tcp->window);
	connections[ccounter].meanwin = (float)ntohs(tcp->window);

	/*printf("Created connection %d with sAddr = %s dAddr = %s sPort = %d dPort = %d", ccounter, connections[ccounter].sAddr, connections[ccounter].dAddr, connections[ccounter].sPort, connections[ccounter].dPort);
	printf("seqnum = %u\n\n\n", connections[ccounter].seqnum);*/

/*

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
	tcp->urg_ptr);*/
	ccounter++;
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
	//printf("Comparing %s ---- %s\n", srcadd, dstadd);
	//Loop through all existing connections, checking if the new packet matches them
	for (i = 0; i < ccounter; i++){
		//Check if addresses are the same -> packet from src to dst
		if(strstr(connections[i].sAddr, srcadd)!=NULL && strstr(connections[i].dAddr, dstadd)){
			//Checks that the ports are the same
			if(connections[i].sPort == (uint16_t)ntohs(tcp->source) && connections[i].dPort == (uint16_t)ntohs(tcp->dest)){
				updateconnection(ts, ip, tcp, i, 0);
				return;
			}
		}
		//Checks if addresses are reversed -> packet from dst to src
		if(strstr(connections[i].sAddr, dstadd)!=NULL && strstr(connections[i].dAddr, srcadd)){
			
			//Checks that the ports are the same (but reversed)
			if(connections[i].sPort == (uint16_t)ntohs(tcp->dest) && connections[i].dPort == (uint16_t)ntohs(tcp->source)){
				updateconnection(ts, ip, tcp, i, 1);
				return;
			}
			//printf("FALSE MATCH");
		}
	}
	//if no matches are found, create a new connection
	createconnection(ts, ip, tcp);
}
//Adds new packet information to an existing connection
void updateconnection(struct timeval ts, struct ip *ip, struct tcphdr *tcp, int i, int dir){
	//if the connection is already complete, stop looking at it
	if(connections[i].S == 2 && connections[i].F==2) return;
	//printPackets(ip, tcp, ts);
	//printf("Adding to connection %i\n", i); 
	//update the packet counters
	if(dir == 0) connections[i].stodpackets++;
	else connections[i].dtospackets++;
	connections[i].packets = connections[i].stodpackets + connections[i].dtospackets;
	//update the time
	long time = ts.tv_sec * 1000000L + ts.tv_usec;
	if(time < connections[i].start) connections[i].start = time;
	if(time > connections[i].end) connections[i].end = time;
	connections[i].duration = connections[i].end - connections[i].start;


	//update the data bytes
	if(dir == 0) connections[i].stodbytes += (unsigned int)tcp->doff*4;
	if(dir == 1) connections[i].dtosbytes += (unsigned int)tcp->doff*4;
	connections[i].bytes = connections[i].stodbytes + connections[i].dtosbytes;

	//update the status
	//if syn flag is found from destination
	if((unsigned int)tcp->syn == 1 && dir == 1) connections[i].S++;
	//if fin flag is found
	if((unsigned int)tcp->fin == 1){
		//from sender
		if(dir == 0) connections[i].sendf=1;
		//from destination
		if(dir == 1) connections[i].dstf=1;
	}
	//Ensures that F=2 is only set when a fin flag is found from both sides
	connections[i].F = connections[i].sendf + connections[i].dstf;
	if((unsigned int)tcp->rst == 1) connections[i].reset = 1;
	//update window stuff
	int window = ntohs(tcp->window);	
	if(connections[i].minwin > window) connections[i].minwin = window;
	if(connections[i].maxwin < window) connections[i].maxwin = window;
	connections[i].totalwin += window;
	connections[i].meanwin = (float)connections[i].totalwin/connections[i].packets;
	//Stuff to do with RTT
}


//Prints the formatted output from the connection
void printconnection(int i, struct connection c){
	
	//Create a status string
	char *status = malloc(4 * sizeof(char));
	
	printf("Connection: %d\nSource Address: %s\nDestination address: %s\nSource Port: %d\nDestination Port: %d\nStatus: S%dF%d\n", i,c.sAddr, c.dAddr, c.sPort, c.dPort, c.S, c.F);
	
	if(c.S >= 1 && c.F >= 1){
		printf("Start time: %ld\n", c.start);
		printf("End time: %ld\n", c.end);
		printf("Duration: %f\n", (float)c.duration/1000000);
		
		printf("Number of packets sent from Source to Destination: %d\n", c.stodpackets);
		printf("Number of packets sent from Destination to Source: %d\n", c.dtospackets);
		printf("Total number of packets: %d\n",c.packets);


		printf("Number of data bytes sent from Source to Destination: %d\n", c.stodbytes);
		printf("Number of data bytes sent from Destination to Source: %d\n", c.dtosbytes);
		printf("Total number of data bytes: %d\n", c.bytes);
	}	
	printf("END\n+++++++++++++++++++++++++++++++++\n.\n.\n.\n");
	//printf("NOT FOR SUBMISSION\nSequence number = %u\nAck Number = %u\n\n", c.seqnum, c.acknum);
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

//For debugging, prints all the relevant information about the packet headers
void printstatus(){
	printf("Total number of connections: %d\n", ccounter);
}
void printPackets(struct ip *ip, struct tcphdr *tcp, struct timeval ts){
	int i = 0;
	//Deals with the tcp header and timestamp
	printf("TCP  Timestamp:%ld\nTCP src_port=%u dst_port=%u seq = %u  ack seq = %u\nflags = %d%d\nWindow = %d Checksum = %d Urg = %d\n" ,
	(ts.tv_sec + ts.tv_usec/1000000L),
	ntohs(tcp->source),
	ntohs(tcp->dest),
	ntohl(tcp->seq),
	ntohl(tcp->ack_seq),
	//(unsigned int)tcph->doff,(unsigned int)tcph->doff*4),
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
