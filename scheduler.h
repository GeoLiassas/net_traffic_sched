#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "dclist.h"

typedef struct traffic_data {
    unsigned char *pkt;
    unsigned int size;              /* Size of the packet */
    int priority;                   /* Priority of the packet */
    unsigned long long time;        /* In millisecond */
    struct lnode list;              /* Internel list structure */
} tfc_t;

int schedule(tfc_t*); 

#define MS_IP "192.168.10.1"
#endif

