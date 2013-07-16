#include "list.h"

list_node_t
*list_init()
{
    list_node_t     *head;

    head = malloc(sizeof(list_node_t));
    if (head == NULL)
    {
        fprintf(stderr, "Failed to create the list.\n");
        exit(EXIT_FAILURE);
    }
    head->next = NULL;
    return head;
}

void
*list_search(list_node_t *h, list_node_t *k)
{
    if (h == NULL || k == NULL)
    {
        fprintf(stderr, "Failed to search the list, because of the error input.\n");
        exit(EXIT_FAILURE);
    }

    if (h->next == NULL)
        return h;
    list_node_t *l = h->next;
    while (l->next != NULL)
    {
        if (l->src == k->src && l->dst == k->dst &&
            l->sport == k->sport && l->dport == k->dport)
            return l;
        l = l->next;
    }
    // return the tail of list
    // it's dangrous, the tail store data
    return l;
}

void
list_insert(list_node_t *h, list_node_t *v)
{
    list_node_t *ret = list_search(h, v);
    if (ret->next != NULL && ret->src == v->src &&
                             ret->dst == v->dst &&
                             ret->sport == v->sport &&
                             ret->dport == v->dport)
    {
        ret->pkt_count += v->pkt_count;
        ret->flow_count += v->flow_count;
        ret->time = v->time;
        free(v);
    }else{
        ret->next = v;
        v->next = NULL;
    }
}

void
list_destory(list_node_t *h)
{
    list_node_t *l = h->next;
    list_node_t *tmp;
    while (l->next != NULL)
    {
        tmp = l;
        l = l->next;
        free(tmp);
    }
    free(l);
}
