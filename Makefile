
all: pcap

pcap: pcap.c
	cc -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -lpcap -Wall -g -o pcap pcap.c

clean:
	rm -rf pcap
