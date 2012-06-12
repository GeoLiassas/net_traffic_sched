#ifndef DCLIST_H
#define DCLIST_H

/*
 * A double cricular linked list implementation which refers to
 * kernel linux/list.h
 */


struct lnode {
    struct lnode *prev;
    struct lnode *next;
    unsigned int id;
};

static inline void dclist_init_head(struct lnode *l)
{
    l->next = l;
    l->prev = l;
}

static inline void dclist_add(struct lnode *new_node, struct lnode *head)
{
    new_node->prev = head->prev;
    new_node->next = head;
    head->prev->next = new_node;
    head->prev = new_node;
}

static inline void dclist_r_add(struct lnode *nw, struct lnode *head)
{
    nw->next = head->next;
    nw->prev = head;
    head->next->prev = nw;
    head->next = nw;
}

#define DCLIST_INIT(name) \
    {&(name), &(name)}

#define dclist_foreach(csr, head) \
    for (csr = (head)->next; csr != (head); csr = csr->next)

#define dclist_foreach_safe(csr, n, head) \
    for (csr = (head)->next, n = (csr)->next; csr != (head); \
         csr = n, n = csr->next)

#define dclist_rforeach(csr, head) \
    for (csr = (head)->prev; csr != (head); csr = csr->prev)

#define dclist_outer(lptr, type, member_name) \
    container_of(lptr, type, member_name)

#ifndef container_of
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif /* container_of */

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif /* offsetof */

#endif
