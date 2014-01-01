CC=gcc
CFLAGS=-I.
DEPS=ssh_server.h
OBJ=ssh_server.o
LIBS=-lssl -lcrypto

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

guptSSHServer : $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 

.PHONY: clean

clean : 
	rm -f guptSSHServer $(OBJ) *.o .*.swp .*.swo .*.swn 
