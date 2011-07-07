CC = gcc
CFLAG = -g -Wall

all: scheduler

scheduler: scheduler.o ts_pcap.o
	$(CC) $(CFLAGS) $^ -o $@

scheduler.o : scheduler.h
ts_pcap.o : scheduler.h


clean:
	/bin/rm -f *.o

