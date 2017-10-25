C=gcc
CFLAGS=
LDFLAGS=
EXEC=packet_dissector

all: $(EXEC)

packet_dissector: packet_dissector.c
		$(CC) -o $@ $^ $(LDFLAGS)

clean:
		rm -rf *.o
