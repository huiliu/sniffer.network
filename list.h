#ifndef __SNIFFER_LIST__
#define __SNIFFER_LIST__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>

typedef struct __list_node__ {
    uint32_t    src;            /* src ip */
    uint32_t    dst;            /* dest ip */
    uint16_t    sport;          /* src port */
    uint16_t    dport;          /* dest port */
    uint8_t     p;              /* protocl type */
    uint8_t     tos;            /* type of server for ip head */
    uint64_t    pkt_count;      /* packet count */
    uint64_t    flow_count;     /* flow count by bytes */
    uint32_t    time;          /* timestamp of the lastest packet */
    struct __list_node__ *next;
}list_node_t;


list_node_t *list_init();
void * list_search(list_node_t *, list_node_t *);
void list_insert(list_node_t *, list_node_t *);
void list_destory(list_node_t *);

#endif
