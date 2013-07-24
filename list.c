#include "list.h"

list_t
*list_init(list_t *list)
{
    list_t *plist = NULL;
    if ((plist = malloc(sizeof(list_t))) == NULL)
    {
        fprintf(stderr, "Failed to create the list.\n");
        exit(EXIT_FAILURE);
    }

    plist->head = malloc(sizeof(list_node_t));
    if (plist->head == NULL)
    {
        fprintf(stderr, "Failed to create the head of list.\n");
        exit(EXIT_FAILURE);
    }

    plist->head->next = NULL;
    plist->tail = plist->head;

    if (list != NULL)
        free(list);
    list = plist;
    return plist;
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
list_insert(list_t *l, list_node_t *v)
{
    l->tail->next = v;
    l->tail = v;
}

void
list_destory(list_t *l)
{
    list_node_t *tmp;
    while (l->head->next != NULL)
    {
        tmp = l->head;
        l->head = tmp->next;
        free(tmp);
    }
    free(l->head);
}
