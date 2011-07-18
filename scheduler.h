#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "dclist.h"

typedef struct traffic_data {
    unsigned long long time;        /* In millisecond */
    unsigned int size;              /* Size of the packet */
    int priority;                   /* Priority of the packet */
    struct lnode list;              /* Internel list structure */
    unsigned char *pkt;
} tfc_t;

int schedule(tfc_t*, long, long); 

#define MS_IP "192.168.10.1"
#endif

