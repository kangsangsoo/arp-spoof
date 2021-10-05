LDLIBS=-lpcap

all: send-arp

main.o : send-arp.h

send-arp: main.o arphdr.o ethhdr.o ip.o mac.o send-arp.h -lpthread
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o
