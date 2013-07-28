
#ifndef __SNIFFER__
#define __SNIFFER__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>


typedef struct __list_node__
{
    uint32_t    src;            /* src ip */
    uint32_t    dst;            /* dest ip */
    uint16_t    sport;          /* src port */
    uint16_t    dport;          /* dest port */
    uint8_t     p;              /* protocl type */
    uint8_t     tos;            /* type of server for ip head */
    uint64_t    pkt_count;      /* packet count */
    uint64_t    flow_count;     /* flow count by bytes */
    time_t      time;          /* timestamp of the lastest packet */
    struct __list_node__ *next;
}list_node_t;

typedef struct __ip_sum__
{
    uint32_t    ip;
    uint64_t    pkt_in;
    uint64_t    pkt_out;
    uint64_t    flow_in;
    uint64_t    flow_out;
}ip_traffic;

#define SNAP_LEN                54
#define OUTPUT_TIME_INTERVAL    60
#define DEV_NAME_LEN            5
#define BUFF_LEN                DEV_NAME_LEN
#define PACKET_MAX_COUNT        500000

#define USAGE(void)             printf("usage: %s <-d dev> <-i interval>\n", argv[0]);\
                                exit(EXIT_FAILURE)
#define MALLOC(fd, size)        if (((fd) = malloc(size)) == NULL) exit(EXIT_FAILURE)

#endif
