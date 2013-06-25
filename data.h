#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>



#ifndef _ON_WIND_DATA_
#define _ON_WIND_DATA_

typedef struct _ow_dest {
    uint32_t    addr;
    uint16_t    sport;
    uint16_t    dport;
    uint8_t     p;
    uint64_t    in;
    uint64_t    out;
    clock_t     time;
    struct _ow_dest *next;
}ow_dest;

struct ow_src {
    uint32_t    src;
    uint8_t[6]  mac;
    uint64_t    in;
    uint64_t    out;
    uint16_t    count;
    uint64_t    time;
    struct _ow_dest *list;
};

ow_dest *head, *tail;

ow_dest *search(ow_dest *h, ow_dest *data) {
    ow_dest *c = h;

    while (c->next != NULL) {
        c = c->next;
        if (c->addr == data->addr && c->sport == data->sport &&
                                                    c->dport == data->dport)
            return c;
    }

    return NULL;
}

void append(ow_dest *t, ow_dest *data) {
    t->next = data;
    t = data;
}

void update(ow_dest *h, ow_dest *data) {
    ow_dest *s = search(h, data);

    if (s != NULL) {
        s->in += data->in;
        s->out += data->out;
        s->time = data->time;
    }else {
        append(h, data);
    }
}

#endif
