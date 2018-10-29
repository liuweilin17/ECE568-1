CC := gcc
CFLAGS := -Wall
LIBS := -lssl -lcrypto
LDFLAGS := $(LIBS)
RM := rm -f

sources := client.c server.c sslutinity.c
targets := client server 

.PHONY: clean default all

default: all
all: $(targets)

client: client.o sslutinity.o
	$(CC) $(LDFLAGS) -o client client.o sslutinity.o

server: server.o sslutinity.o
	$(CC) $(LDFLAGS) -o server server.o sslutinity.o


client.o: client.c
	$(CC) $(CFLAGS) -c -o client.o client.c

server.o: server.c
	$(CC) $(CFLAGS) -c -o server.o  server.c

sslutinity.o: sslutinity.c
	$(CC) $(CFLAGS) -c -o sslutinity.o  sslutinity.c

clean:
	$(RM) $(targets) $(sources:.c=.o) *~

