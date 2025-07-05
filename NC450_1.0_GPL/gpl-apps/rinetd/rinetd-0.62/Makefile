CFLAGS=-DLINUX -g
CC=$(CROSS_COMPILE)gcc

rinetd: rinetd.o match.o
	$(CC) rinetd.o match.o -o rinetd
rinetd.o:
	$(CC) -c rinetd.c
match.o:
	$(CC) -c match.c
clean:
	rm -f *.o
	rm -f rinetd
