#ifndef SCHEDULER_H
#define SCHEDULER_H

typedef struct traffic_data {
    struct traffic_data *next;
    struct traffic_data *prev;
    unsigned char *pkt;
    int size;
    int priority;
    int time;
} tfc_t;

int schedule(tfc_t* tail); 

#endif

