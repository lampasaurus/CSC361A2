all: program1

program1: 
	clear
	gcc -w -o parser parser.c -lpcap
clean:
	rm -f parser
run:
	./parser trace.cap
