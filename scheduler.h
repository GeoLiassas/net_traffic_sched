#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "dclist.h"

typedef struct traffic_data {
    unsigned long long time;        /* In millisecond */
    unsigned int size;              /* Size of the packet */
    int priority;                   /* Priority of the packet */
    struct lnode list;              /* Internel list structure */
    unsigned long id;               /* Identity of this packet */
    unsigned char *pkt;
} tfc_t;

#define tfc_id(tp) \
    (tp)->pkt

/**
 * Schedule fuction, accepting a list of trafic data, and re-arranging
 * the sending time for each of them in order to achieve bursting.
 */
int schedule(tfc_t*, long, long); 

#define MS_IP "192.168.10.1"
#endif

