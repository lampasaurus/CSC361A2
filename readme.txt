To compile:  make
To run:
	Option 1: make run
	Will run using ./parser cap-feb-6
	
	Option 2: ./parser <cap file>

Data Structures
Creates a (huge) array to store each of the following:
IP headers
TCP Headers
Time Values
Connections

TCP headers are defined by netinet/tcp.h, and contain all tcp information from the packets within the
trace file EXCEPT the IP address
IP headers are ip structures defined by netinet/ip.h and contain only the IP address
Time values are stored as timeval structures

The program begins by reading in every packet extracted using pcap.h one by one
It then extracts the ip header, tcp header and time from each packet
It then uses the extracted information to create connection data structures.  A connection contains all relevant TCP and IP information
in a format that is usable by me.
When a packet not belinging to an existing connection is found, a new connection is created
When a packet belonging to an existing connection is found, it's information is compared with the existing information in the connection,
and the existing information is updated if needed.
After that, it simply goes through each connection and writes formatted information from them
