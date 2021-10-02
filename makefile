LDLIBS=-lpcap

all: send-arp

main.o : send-arp.h

send-arp: send-arp.h main.o arphdr.o ethhdr.o ip.o mac.o -lpthread
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o
