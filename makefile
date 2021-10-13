LDLIBS=-lpcap

all: arp-spoof

main.o : send-arp.h

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o send-arp.h -lpthread 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ 

clean:
	rm -f send-arp *.o
