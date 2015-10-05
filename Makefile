CC=gcc
CFLAGS=-g -Wall
EXECUTABLE=tcptest

all: $(EXECUTABLE)

$(EXECUTABLE): test.o tcp.o
	$(CC) test.o tcp.o -o $(EXECUTABLE)

test.o: test.c
	$(CC) -c $(CFLAGS) test.c -o test.o

tcp.o: tcp.c
	$(CC) -c $(CFLAGS) tcp.c -o tcp.o

clean:
	rm -f $(EXECUTABLE) *~ *.o
