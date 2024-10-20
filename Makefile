CC = g++
CFLAGS = -std=c++17 -Wall
LDFLAGS = -lldap -llber

all: twmailer-pro-server twmailer-client

twmailer-pro-server: twmailer-server.cpp
	$(CC) $(CFLAGS) -o twmailer-pro-server twmailer-server.cpp $(LDFLAGS)

twmailer-client: twmailer-client.cpp
	$(CC) $(CFLAGS) -o twmailer-client twmailer-client.cpp

clean:
	rm -f twmailer-pro-server twmailer-client