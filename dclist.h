#ifndef DC_LIST_H
#define DC_LIST_H

struct lnode {
    struct lnode *prev;
    struct lnode *next;
    unsigned int id;
};

inline void dclist_add(struct lnode *new_node, struct lnode *head)
{
    new_node->prev = head->prev;
    new_node->next = head;
    head->prev->next = new_node;
    head->prev = new_node;
}

inline void dclist_r_add(struct lnode *nw, struct lnode *head)
{
    nw->next = head->next;
    nw->prev = head;
    head->next->prev = nw;
    head->next = nw;
}

#define dclist_foreach(csr, head) \
    for (csr = (head)->next; csr != (head); csr = csr->next)

#define dclist_rforeach(csr, head) \
    for (csr = (head)->prev; csr != (head); csr = csr->prev)

#define dclist_outer(lptr, type, member_name) \
    container_of(lptr, type, member_name)
    
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)


#endif
