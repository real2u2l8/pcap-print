LDLIBS += -lpcap

all: pcap-test

pcap-print: pcap-test.c

clean:
	rm -f pcap-test *.o
