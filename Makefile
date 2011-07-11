CC = gcc
CFLAGS = -g -Wall

all: scheduler test

scheduler: scheduler.o ts_pcap.o
	$(CC) $(CFLAGS) -lpcap $^ -o $@

test: test_pcap

test_pcap: test_pcap.o ts_pcap.o
	$(CC) $(CFLAGS) -lpcap $^ -o $@

scheduler.o : scheduler.h dclist.h
ts_pcap.o : scheduler.h


clean:
	/bin/rm -f *.o *.gch

