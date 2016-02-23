#include <stdio.h>
#include <pcap.h>
#include<net/ethernet.h>
#include<netinet/tcp.h>
#define LINE_LEN 16
#define P_LEN 1000
//If source IP, source port, destination IP, destination port are all the same, it's part of the same connection

//Only get statistics from complete TCP connections
//https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut7.html
//http://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
//Skip the IP and ethernet headers
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void print_ip_packet(const u_char * , int);
int packetcounter = 0;

int main(int argc, char *argv[]){
	pcap_t *capfile;
	struct pcap_pkthdr *header;
	char errbuf[PCAP_ERRBUF_SIZE];
   	u_char *pkt_data;
  	u_int i=0;

	if (argc < 2) {
    		fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
    		return(-1);
  	}
	//Opens the dump file
	capfile = pcap_open_offline(argv[1], errbuf);
   	if (capfile == NULL) {
     		fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf);
     		return(-1);
   	}
	pcap_loop(capfile , -1 , process_packet , NULL);
	//test(capfile, header, pkt_data);
	return 0;
}
void test(pcap_t *capfile, struct pcap_pkthdr *header, u_char *pkt_data){
	int res;	
	while(res = pcap_next_ex(capfile, &header, &pkt_data)>=0){
		printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
	}
}

int process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    	int size = header->len;
    	//Get the IP Header part of this packet , excluding the ethernet header
    	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	//Check the Protocol and do accordingly...
	switch (iph->protocol){
        case 6:  //TCP Protocol
            	print_tcp_packet(buffer , size);
		packetcounter++;
            	break;
         
        default: //Some Other Protocol like ARP etc.
		fprintf(stderr, "Not a TCP header");
            	break;
    	}
}
void print_tcp_packet(const u_char * Buffer, int Size){
}
void print_ip_header(const u_char buffer, int size){

}
