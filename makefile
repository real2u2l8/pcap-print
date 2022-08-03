LDLIBS += -lpcap

all: pcap-print

pcap-print: pcap-print.c

clean:
	rm -f pcap-print *.o
