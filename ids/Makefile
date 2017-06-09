CC=gcc
CFLAGS=-Werror -Wall 
LIBS= -lnfnetlink -lnetfilter_queue
capture:
	$(CC) $(CFLAGS) capture.c -o capture $(LIBS)
ids:
	$(CC) $(CFLAGS) ids.c -o ids $(LIBS)
clean:
	rm ids capture
