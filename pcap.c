#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <pcap.h>
#include <pcap-bpf.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib.h>

#define SNAP_LEN    1518

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct ether_header *ethernet;

    ethernet = (struct ether_header *)packet;
    /*
    printf("SRC MAC: %X:%X:%X:%X:%X:%X, DST MAC: %X:%X:%X:%X:%X:%X\n",
                ethernet->ether_shost[0], ethernet->ether_shost[1], 
                ethernet->ether_shost[2], ethernet->ether_shost[3], 
                ethernet->ether_shost[4], ethernet->ether_shost[5], 
                ethernet->ether_dhost[0], ethernet->ether_dhost[1], 
                ethernet->ether_dhost[2], ethernet->ether_dhost[3], 
                ethernet->ether_dhost[4], ethernet->ether_dhost[5]
            );
    */

    const struct ip *ip;
    char ip_src[16];

    ip = (struct ip*)(packet + ETHER_HDR_LEN);
    size_t ip_h_size = ip->ip_hl * 4;

    if ( ip_h_size < 20) {
        fprintf(stderr, "Invalid IP header length\n");
        return;
    }

    strcpy(ip_src, inet_ntoa(ip->ip_src));

    /*
    printf("SRC IP: %s\n", ip_src);
    printf("DST IP: %s\n", inet_ntoa(ip->ip_dst));
    */
    uint16_t sport, dport;
    const struct tcphdr *tcp;
    const struct udphdr *udp;

    switch (ip->ip_p) {
        case IPPROTO_TCP:
            //printf("\e\[31mTCP\e\[0m");

            tcp = (struct tcphdr *)(packet + ETHER_HDR_LEN + ip_h_size);

            sport = ntohs(tcp->source);
            dport = ntohs(tcp->dest);
            break;
        case IPPROTO_UDP:
            //printf("\e\[31mUDP\e\[0m");
            udp = (struct udphdr *)(packet + ETHER_HDR_LEN + ip_h_size);

            sport = ntohs(udp->source);
            dport = ntohs(udp->dest);
            break;
        case IPPROTO_ICMP:
            //printf("\e\[31mICMP\e\[0m %u\n", header->len);
            sport = 0;
            dport = 0;
            break;
        default:
            printf("Unknow PROTO %u\n", header->len);
            sport = 0;
            dport = 0;
    }

    syslog(LOG_INFO, "%u %s %s %d %d %d %d\n",
                                    header->len, ip_src, inet_ntoa(ip->ip_dst),
                                    ip->ip_p, ip->ip_tos, sport, dport);
}


int main(int argc, char **argv)
{
    char *dev, err_buff[PCAP_ERRBUF_SIZE];

    // 1. find the active interface for capturing data
    if ((dev = pcap_lookupdev(err_buff)) == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", err_buff);
        return 1;
    }

    // printf("%s\n", dev);

    // 2. open the interface
    pcap_t *handle = NULL;
    bpf_u_int32 net, mask;

    if ((handle = pcap_open_live(dev, SNAP_LEN, 0, 1000, err_buff)) == NULL) {
        fprintf(stderr, "Failed to open the device %s\n", dev);
        return 2;
    }

    if (pcap_lookupnet(dev, &net, &mask, err_buff) == -1) {
        fprintf(stderr, "Failed to get net.\n");
        return 3;
    }

    // 3. complie the filter
    char filter[] = "ip";
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "failed to compile the filter %s: %s\n",
                                                filter, pcap_geterr(handle));
        return 4;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "failed to set filter %s: %s\n", filter,
                                                        pcap_geterr(handle));
        return 4;
    }

    // 4. capture the packet
    int num_packets = 20;

    pcap_loop(handle, num_packets, got_packet, NULL);
    
    // 5. stop capturing packets and free memory.
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
