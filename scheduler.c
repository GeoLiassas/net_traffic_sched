#include <stdio.h>
#include <stdlib.h>
#include "scheduler.h"

#define BW_PER_SEC 1024000
#define MAX_INTERVAL 100

extern tfc_t *build_traffic_pcap(char *);

int schedule(tfc_t* head) 
{

    tfc_t *itr, *itr_prev;
    struct lnode *lp;
    int pkt_interval;
    int pkt_trans_time;

    dclist_rforeach(lp, &head->list) {
        itr = dclist_outer(lp, tfc_t, list);

        if (lp->prev == &head->list)
            break;
        itr_prev = dclist_outer(lp->prev, tfc_t, list);
        
        pkt_interval = itr->time - itr_prev->time;
        pkt_trans_time = (int)((double)itr_prev->size / BW_PER_SEC * 1000);
        printf(" %d | %d \n", pkt_interval, pkt_trans_time);
        if (pkt_interval <= itr_prev->priority * MAX_INTERVAL 
            && pkt_interval >= pkt_trans_time) {
            itr_prev->time = itr->time - pkt_trans_time;
        }
        
    }
    return 0;
}

int main()
{
    /*  DEBUG DCLIST
    struct lnode head = {&head, &head};
    struct lnode *lp, *lc;
    head.id = 0;
    
    lp = (struct lnode *) malloc(sizeof(struct lnode));
    lp->id = 1;
    dclist_r_add(lp, &head);

    lp = (struct lnode *) malloc(sizeof(struct lnode));
    lp->id = 2;
    dclist_r_add(lp, &head);

    lp = (struct lnode *) malloc(sizeof(struct lnode));
    lp->id = 3;
    dclist_r_add(lp, &head);

    dclist_foreach(lc, &head) {
        printf("%d\n", lc->id);
    }

    printf("=======\n");
    dclist_rforeach(lc, &head) {
        printf("%d\n", lc->id);
    }

    printf("####%lu\n", offsetof(tfc_t, pkt));
    printf("####%lu\n", offsetof(tfc_t, size));
    printf("####%lu\n", offsetof(tfc_t, priority));
    printf("####%lu\n", offsetof(tfc_t, time));
    printf("####%lu\n", offsetof(tfc_t, list));
    */

    tfc_t *headt, *tp;
    struct lnode *ln;
    int count = 0;
    FILE *pre, *post;

    headt = build_traffic_pcap("pcap_data/browse2.pcap");
    pre = fopen("pre.test.output", "w+");
    dclist_foreach(ln, &headt->list) {
        tp = dclist_outer(ln, tfc_t, list);
        fprintf(pre, "%d|%llu\n", count++, tp->time);
    }
    fclose(pre);
    
    count = 0;
    schedule(headt);
    post = fopen("post.test.output", "w+");
    dclist_foreach(ln, &headt->list) {
        tp = dclist_outer(ln, tfc_t, list);
        fprintf(post, "%d|%llu\n", count++, tp->time);
    }
    fclose(post);

    return 0;
}
