#include <stdio.h>
#include "scheduler.h"

#define BW_PER_SEC 1024
#define MAX_INTERVAL 100

int schedule(tfc_t* tail) 
{
    tfc_t *itr, *itr_prev;
    int pkt_interval;
    int pkt_trans_time;
    for (itr = tail; itr->prev != NULL; itr = itr->prev) {
        itr_prev = itr->prev;
        
        if (!itr_prev) 
            break;
        
        pkt_interval = itr->time - itr_prev->time;
        pkt_trans_time = (int)((double)itr_prev->size / BW_PER_SEC * 1000);

        if (pkt_interval <= itr_prev->priority * MAX_INTERVAL 
            && pkt_interval >= pkt_trans_time) {
            itr_prev->time = itr->time - pkt_trans_time;
        }
    }
    return 0;
}

int main()
{
}
