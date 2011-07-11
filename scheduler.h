#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "dclist.h"

typedef struct traffic_data {
    unsigned char *pkt;
    int size;
    int priority;
    int time;
    struct lnode list;
} tfc_t;

int schedule(tfc_t*); 

#endif

