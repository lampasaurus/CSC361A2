all: program1

program1: 
	gcc -w -o parser parser.c -lpcap
clean:
	rm -f parser
