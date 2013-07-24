

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <pcap-bpf.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>

#include <event.h>
#include <time.h>

#include "sniffer.h"

list_node_t  packet_list[PACKET_MAX_COUNT];
uint32_t packet_list_len = 0;
pcap_t *pcap_dest = NULL;
int pcap_fd;
struct event_base *evbase;
char *o_file_name = NULL;
char *dev = NULL;
FILE *fd = NULL;
uint16_t    interval = 0;

char
*generate_file_name()
{
    void *buff;

    if ((buff = malloc(sizeof(char))) == NULL)
    {
        fprintf(stderr, "failed to allocate memory!\n");
        exit(EXIT_FAILURE);
    }
    time_t t = time(NULL);
    strftime(buff, 20, "packet_%Y%m%d%H%M", localtime(&t));
    return buff;
}

void
list_walk()
{

    if (fd == NULL)
    {
        fprintf(stderr, "invalidate file handle.[output]\n");
        exit(EXIT_FAILURE);
    }
#if defined(__x86_64__)
    char *fmt = "%s %s %d %d %lu %lu %lu\n";
#else
    char *fmt = "%s %s %d %d %llu %llu %lu\n";
#endif

    char ip_src[16];
    list_node_t *l = packet_list;
    uint32_t i;

    for (i = 0; i < packet_list_len; i++)
    {
        strcpy(ip_src, inet_ntoa(*(struct in_addr *)&l->src));
        fprintf(fd, fmt,
                    ip_src, inet_ntoa(*(struct in_addr *)&l->dst),
                    l->sport, l->dport,
                    l->pkt_count, l->flow_count, l->time);
        l++;
    }
    packet_list_len = 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                                                        const u_char *packet)
{
    const struct ether_header   *ethernet;
    const struct ip             *ip;
    const struct tcphdr         *tcp;
    const struct udphdr         *udp;
    list_node_t     *node;
    uint16_t        sport,
                    dport;
    char            ip_src[16],
                    ip_dst[16];

    
    if (packet_list_len >= PACKET_MAX_COUNT)
    {
        fprintf(stderr, "The count of packets exceed %d, Packets will be drop\n",
                                                            PACKET_MAX_COUNT);
        return;
    }

    node = packet_list + packet_list_len;
    packet_list_len++;
    node->time = time(NULL);

    ethernet = (struct ether_header *)packet;

    ip = (struct ip*)(packet + ETHER_HDR_LEN);
    size_t ip_h_size = ip->ip_hl * 4;

    if ( ip_h_size < 20) {
        fprintf(stderr, "Invalid IP header length\n");
        return;
    }

    node->src = ip->ip_src.s_addr;
    node->dst = ip->ip_dst.s_addr;
    node->p = ip->ip_p;
    node->tos = ip->ip_tos;

    strcpy(ip_src, inet_ntoa(ip->ip_src));
    strcpy(ip_dst, inet_ntoa(ip->ip_dst));

    /*
    printf("SRC IP: %s\n", ip_src);
    printf("DST IP: %s\n", inet_ntoa(ip->ip_dst));
    */

    switch (ip->ip_p) {
        case IPPROTO_TCP:
            //printf("\e\[31mTCP\e\[0m");
            tcp = (struct tcphdr *)(packet + ETHER_HDR_LEN + ip_h_size);

            node->sport = sport = ntohs(tcp->th_sport);
            node->dport = dport = ntohs(tcp->th_dport);
            break;
        case IPPROTO_UDP:
            //printf("\e\[31mUDP\e\[0m");
            udp = (struct udphdr *)(packet + ETHER_HDR_LEN + ip_h_size);

            node->sport = sport = ntohs(udp->uh_sport);
            node->dport = dport = ntohs(udp->uh_dport);
            break;
        case IPPROTO_ICMP:
            //printf("\e\[31mICMP\e\[0m %u\n", header->len);
            node->sport = node->dport =  sport = dport = 0;
            break;
        default:
            printf("Unknow PROTO %u\n", header->len);
            sport = 0;
            dport = 0;
    }

    node->pkt_count++;
    node->flow_count = header->len;
}

/*
 * event timer handle use to output data
 * 
 */
void ev_time_handle(int fdd, short event, void *argv)
{

    if(fflush(fd) != 0)
    {
        fprintf(stderr, "failed to open file for store data\n");
        exit(EXIT_FAILURE);
    }

    list_walk();
    fclose(fd);

    o_file_name = generate_file_name();
    if ((fd = fopen(o_file_name, "w")) == NULL) {
        fprintf(stderr, "failed to open file for store data\n");
        exit(EXIT_FAILURE);
    }

    struct event *evtime = argv;
    struct timeval tv;

    evutil_timerclear(&tv);
    tv.tv_sec = OUTPUT_TIME_INTERVAL;
    event_add(evtime, &tv);
}

/*
 * event handler use to capture packet
 *
 */
void ev_pkt_handler(int sock, short which, void *argv)
{
    pcap_dispatch(pcap_dest, 1, got_packet, argv);
}

void pcap_init(void)
{
    //char *dev;
    char err_buff[PCAP_ERRBUF_SIZE];

    if (dev == NULL) {
        // 1. find the active interface for capturing data
        if ((dev = pcap_lookupdev(err_buff)) == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", err_buff);
            exit(EXIT_FAILURE);
        }
    }

    // 2. open the interface
    bpf_u_int32 net, mask;

    if ((pcap_dest = pcap_open_live(dev, SNAP_LEN, 0, 1000, err_buff)) == NULL){
        fprintf(stderr, "Failed to open the device %s\n", dev);
        exit(EXIT_FAILURE);
    }

    if (pcap_lookupnet(dev, &net, &mask, err_buff) == -1) {
        fprintf(stderr, "Failed to get net.\n");
        exit(EXIT_FAILURE);
    }

    // 3. complie the filter
    char filter[] = "ip";
    struct bpf_program fp;
    if (pcap_compile(pcap_dest, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "failed to compile the filter %s: %s\n",
                                                filter, pcap_geterr(pcap_dest));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(pcap_dest, &fp) == -1) {
        fprintf(stderr, "failed to set filter %s: %s\n", filter,
                                                        pcap_geterr(pcap_dest));
        exit(EXIT_FAILURE);
    }

    // 4. set the mode of pcap as non-block
    if ((pcap_setnonblock(pcap_dest, 1, err_buff)) != 0) {
        fprintf(stderr, "\e\[31m[Error]\e\[0m: %s\n", err_buff);
        exit(EXIT_FAILURE);
    }

    
    // 5. capture the packet by using libevent and libpcap
    if ((pcap_fd = pcap_get_selectable_fd(pcap_dest)) <= 0) {
        fprintf(stderr, "\e\[31m[Error]\e\[0m: fail to get pcap file description\n");
        exit(EXIT_FAILURE);
    }
}

void
parse_cmd(int argc, char **argv)
{
    int opt;
    if (argc == 1) {
        USAGE();
    }

    while ((opt = getopt(argc, argv, "d:i:h")) != -1) {
        switch (opt) {
            case 'd':
                MALLOC(dev, sizeof(char) * DEV_NAME_LEN);
                strcpy(dev, optarg);
                break;
            case 'i':
                interval = atoi(optarg);
                break;
            case 'h':
                USAGE();
                break;
            default:
                USAGE();
        }
    }

}

int main(int argc, char **argv)
{

    parse_cmd(argc, argv);
    //evbase = event_base_new();

    pcap_init();

    /*
     * libevent-1.4
     *
     */
    struct event evtime;
    struct event pcap_event;
    struct timeval tv;

    o_file_name = generate_file_name();
    if ((fd = fopen(o_file_name, "w")) == NULL) {
        fprintf(stderr, "failed to open file for store data\n");
        exit(EXIT_FAILURE);
    }

    event_init();

    // timer
    evtimer_set(&evtime, ev_time_handle, &evtime);
    evutil_timerclear(&tv);
    tv.tv_sec = interval;
    event_add(&evtime, &tv);

    // registe event for capture packet
    event_set(&pcap_event, pcap_fd, EV_READ | EV_PERSIST,
                                                        ev_pkt_handler, NULL);
    event_add(&pcap_event, NULL);

    event_dispatch();


    /*
     * TODO:
     *      1. free and destory the hash table
     *      2. flush hash_table and remove some connection information
     */

    //printf("%d\n", g_hash_table_size(flow_tbl));
    //hash_table_walk(flow_tbl);
    fclose(fd);
    return 0;
}
