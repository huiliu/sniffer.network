
all: pcap

pcap: pcap.c
	cc -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -lglib-2.0 -levent -lpcap -Wall -g -o pcap pcap.c

clean:
	rm -rf pcap
