CC=gcc
CFLAGS=-g -std=c99 -Wall -Wextra -Wpedantic -D_BSD_SOURCE -pthread
EXECUTABLE=tcptest

all: $(EXECUTABLE)

$(EXECUTABLE): test.o tcp.o tcpdata.o checksum.o utils.o
	$(CC) $(CFLAGS) test.o tcp.o tcpdata.o checksum.o utils.o -o $(EXECUTABLE)

test.o: test.c
	$(CC) -c $(CFLAGS) test.c -o test.o

tcp.o: tcp.c
	$(CC) -c $(CFLAGS) tcp.c -o tcp.o

tcpdata.o: tcpdata.c
	$(CC) -c $(CFLAGS) tcpdata.c -o tcpdata.o

checksum.o: checksum.c
	$(CC) -c $(CFLAGS) checksum.c -o checksum.o
	
utils.o: utils.c
	$(CC) -c $(CFLAGS) utils.c -o utils.o

clean:
	rm -f $(EXECUTABLE) *~ *.o
