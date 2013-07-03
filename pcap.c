

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
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
#include <glib.h>
#include <time.h>

#define SNAP_LEN    1518
#define OUTPUT_TIME_INTERVAL    5

typedef struct __hash_node__ {
    uint32_t    src;            /* src ip */
    uint32_t    dst;            /* dest ip */
    uint16_t    sport;          /* src port */
    uint16_t    dport;          /* dest port */
    uint8_t     p;              /* protocl type */
    uint8_t     tos;            /* type of server for ip head */
    uint64_t    pkt_count;      /* packet count */
    uint64_t    flow_count;     /* flow count by bytes */
    uint32_t     time;          /* timestamp of the lastest packet */
}hash_node_t;


GHashTable  *flow_tbl;
struct event_base *evbase;
pcap_t *pcap_dest = NULL;
int pcap_fd;
const char *o_file_name = "/tmp/flow_data";

FILE *fd = NULL;

/*
 * initiate the globle variable flow_tbl
 *
 */
void hash_table_init(void)
{
    if((flow_tbl = g_hash_table_new(g_str_hash, g_str_equal)) == NULL) {
        fprintf(stderr, "failed to allocate memory for hash table\n");
        exit(EXIT_FAILURE);
    }
}

/*
 * output hash table
 *
 */
void hash_table_walk(GHashTable *ght)
{
    GList *flow_list;
    char ip_src[16];

    if((flow_list = g_hash_table_get_values(ght)) == NULL) {
        fprintf(stderr, "Doesn't capture any packet!\n");
        return;
    }
    /*
     * there maybe 
     *
     */
    rewind(fd);

    while (flow_list->next != NULL) {
        hash_node_t *d = flow_list->data;
        
        strcpy(ip_src, inet_ntoa(*(struct in_addr *)&d->src));

        fprintf(fd, "%s %s %d %d %d %d %lu %lu\n",
                    ip_src, inet_ntoa(*(struct in_addr *)&d->dst),
                    d->sport, d->dport,
                    d->p, d->tos,
                    d->pkt_count, d->flow_count
                );
        flow_list = flow_list->next;
    }

    hash_node_t *d = flow_list->data;
    
    strcpy(ip_src, inet_ntoa(*(struct in_addr *)&d->src));

    fprintf(fd, "%s %s %d %d %d %d %lu %lu\n",
                ip_src,
                inet_ntoa(*(struct in_addr *)&d->dst),
                d->sport, d->dport,
                d->p, d->tos, d->pkt_count, d->flow_count
            );
 
}

/*
 * initiate a hash node structure and return the address for storing data
 *
 */
inline hash_node_t *hash_node_init(void)
{
    hash_node_t* hash_node;

    if ((hash_node = malloc(sizeof(hash_node_t))) == NULL) {
        fprintf(stderr, "allocate hash node memory\n");
        exit(EXIT_FAILURE);
    }

    memset(hash_node, 0, sizeof(hash_node_t));
    hash_node->time = time(NULL);
    return hash_node;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct ether_header   *ethernet;
    const struct ip             *ip;
    const struct tcphdr         *tcp;
    const struct udphdr         *udp;
    hash_node_t     *hash_node,
                    *hn_ip_up,
                    *hn_ip_down;
    uint16_t        sport,
                    dport;
    char            buff[46],
                    ip_src[16];
    const char      *up = "out",
                    *down = "in";

    hash_node = hash_node_init();
    hn_ip_up = hash_node_init();
    hn_ip_down = hash_node_init();

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

    ip = (struct ip*)(packet + ETHER_HDR_LEN);
    size_t ip_h_size = ip->ip_hl * 4;

    if ( ip_h_size < 20) {
        fprintf(stderr, "Invalid IP header length\n");
        return;
    }

    hn_ip_up->src = hash_node->src = ip->ip_src.s_addr;
    hn_ip_down->dst = hash_node->dst = ip->ip_dst.s_addr;
    hash_node->p = ip->ip_p;
    hash_node->tos = ip->ip_tos;

    strcpy(ip_src, inet_ntoa(ip->ip_src));

    /*
    printf("SRC IP: %s\n", ip_src);
    printf("DST IP: %s\n", inet_ntoa(ip->ip_dst));
    */

    switch (ip->ip_p) {
        case IPPROTO_TCP:
            //printf("\e\[31mTCP\e\[0m");
            tcp = (struct tcphdr *)(packet + ETHER_HDR_LEN + ip_h_size);

            hash_node->sport = sport = ntohs(tcp->th_sport);
            hash_node->dport = dport = ntohs(tcp->th_dport);
            break;
        case IPPROTO_UDP:
            //printf("\e\[31mUDP\e\[0m");
            udp = (struct udphdr *)(packet + ETHER_HDR_LEN + ip_h_size);

            hash_node->sport = sport = ntohs(udp->uh_sport);
            hash_node->dport = dport = ntohs(udp->uh_dport);
            break;
        case IPPROTO_ICMP:
            //printf("\e\[31mICMP\e\[0m %u\n", header->len);
            hash_node->sport = hash_node->dport =  sport = dport = 0;
            break;
        default:
            printf("Unknow PROTO %u\n", header->len);
            sport = 0;
            dport = 0;
    }

    hash_node->pkt_count++;
    hn_ip_down->pkt_count = hn_ip_up->pkt_count = hash_node->pkt_count;
    hn_ip_down->flow_count = hn_ip_up->flow_count = hash_node->flow_count
                                                                = header->len;
    
/*
 * insert into the hash table
 *
 */

    hash_node_t *hn = NULL;
    char *key = NULL;

    /* statistics information */ 
    // up trafic
    key = strcat(ip_src, up);
    if ((hn = g_hash_table_lookup(flow_tbl, key)) != NULL) {
        hn->pkt_count++;
        hn->flow_count += header->len;
        free(hn_ip_up);
    }else
        g_hash_table_insert(flow_tbl, key, hn_ip_up);

    // down trafic
    hn = NULL;
    key = strcat(inet_ntoa(ip->ip_dst), down);
    if ((hn = g_hash_table_lookup(flow_tbl, key)) != NULL) {
        hn->pkt_count++;
        hn->flow_count += header->len;
        free(hn_ip_down);
    }else
        g_hash_table_insert(flow_tbl, key, hn_ip_down);

    hn = NULL;
    /* hash key */
    sprintf(buff, "%s%s%d%d%d",ip_src, inet_ntoa(ip->ip_dst),
                                                        ip->ip_p, sport, dport);
    if ((hn = g_hash_table_lookup(flow_tbl, buff)) != NULL) {
        /* connetion information */
        hn->pkt_count++;
        hn->flow_count += header->len;
        free(hash_node);
    }else
        /* new connetion information */
        g_hash_table_insert(flow_tbl, buff, hash_node);

    /*
    fprintf(stdout, "%s %s %d %d %d %d\n",ip_src, inet_ntoa(ip->ip_dst),
                                            ip->ip_p, sport, dport, header->len);
    syslog(LOG_INFO, "%u %s %s %d %d %d %d\n",
                                    header->len, ip_src, inet_ntoa(ip->ip_dst),
                                    ip->ip_p, ip->ip_tos, sport, dport);
    */
}

/*
 * event timer handle use to output data
 * 
 */
void ev_time_handle(int fd, short event, void *argv)
{
    hash_table_walk(flow_tbl);

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
    char *dev;
    char err_buff[PCAP_ERRBUF_SIZE];

    // 1. find the active interface for capturing data
    if ((dev = pcap_lookupdev(err_buff)) == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", err_buff);
        exit(EXIT_FAILURE);
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

int main(int argc, char **argv)
{
    //evbase = event_base_new();
    hash_table_init();

    pcap_init();

    /*
     * libevent-1.4
     *
     */
    struct event evtime;
    struct event pcap_event;
    struct timeval tv;

    if ((fd = fopen(o_file_name, "w")) == NULL) {
        fprintf(stderr, "failed to open file for store data\n");
        exit(EXIT_FAILURE);
    }

    event_init();

    // timer
    evtimer_set(&evtime, ev_time_handle, &evtime);
    evutil_timerclear(&tv);
    tv.tv_sec = OUTPUT_TIME_INTERVAL;
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
