CC = gcc
CFLAGS = -g -Wall

all: scheduler replay_pcap

scheduler: scheduler.o ts_pcap.o
	$(CC) $(CFLAGS) -lpcap $^ -o $@

replay_pcap: replay_pcap.o ts_pcap.o
	$(CC) $(CFLAGS) -lpcap $^ -o $@

scheduler.o : scheduler.h
ts_pcap.o : scheduler.h

clean:
	/bin/rm -f *.o *.gch

