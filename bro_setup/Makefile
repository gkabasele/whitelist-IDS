CC= g++-5
CFLAGS= -std=c++11  -Wall -Werror
LIBS=  -lbroker
BROFLAGS= -b -C -i lo
BRO=bro

all: client_broker

client_broker: client_broker.cpp
	$(CC) $(CFLAGS) -g $< -o $@ $(LIBS)
ids: server_broker.bro
	$(BRO) $(BROFLAGS) $<	
clean:
	rm *.o bro_server
