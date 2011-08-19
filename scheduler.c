#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include "scheduler.h"

#define BW_PER_SEC      "1024000000"    /* byte per second */
#define MAX_INTERVAL    "100"           /* in millisecond */


extern tfc_t *build_traffic_pcap(char *, char *);
extern int result_compare(tfc_t *, char *);

int schedule(tfc_t* head, long bw, long max_interval) 
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
        pkt_trans_time = (int)((double)itr_prev->size / bw);
        if (pkt_interval <= itr_prev->priority * max_interval
            && pkt_interval >= pkt_trans_time) {
            itr_prev->time = itr->time - pkt_trans_time;
        }
        
    }
    return 0;
}



#define PROC_FILE       "/proc/sch_80211/prediction"
/**
 * Transmit traffic data to the kernel space via proc
 */
static int sync_traffic_data(tfc_t *headt)
{
    int proc_fd;
    char text_buf[1024];
    tfc_t *tp;
    struct lnode *ln;

    if ((proc_fd = open(PROC_FILE, O_WRONLY, 0)) == -1) {
        perror("sync_traffic_data: open");
        exit(1);
    }
    dclist_foreach(ln, &headt->list) {
        tp = dclist_outer(ln, tfc_t, list);
        sprintf(text_buf, 
                "%lu\t%llu\t%llu\t%u\t%d\t\n", 
                tp->id, tp->otime, tp->time, tp->size, tp->priority);
        if ((write(proc_fd, text_buf, strlen(text_buf))) == -1) {
            perror("sync_traffic_data: write");
            exit(1);
        }
    }

    if ((write(proc_fd, "723", 4)) == -1) {
        perror("sync_traffic_data: write");
        exit(1);
    }
    close(proc_fd);
    return 0;
}

void usage()
{
    printf("Usage: \n");
    printf("To schedule and sync traffic data to the kernel: \n");
    printf("   ./schduler -g [-i MAX_INTERVAL] [-b BANDWIDTH] "
                                "[-t TARGET_IP] [-s PACKET_SOURCE]\n");

    printf("For result comparasion: \n");
    printf("   ./schduler -c FILE_FOR_COMPARE [-i MAX_INTERVAL] [-b BANDWIDTH] "
                                "[-t TARGET_IP] [-s PACKET_SOURCE]\n");
    printf("\nOptions: \n");
    printf("   -i Max packet interval in milliseconds, DEFAULT = 100\n");
    printf("   -b Bandwidth in byte/sec, DEFAULT = 1024000000\n");
    printf("   -t IP of the target mobible station, DEFAULT = 192.168.10.10\n");
    printf("   -s Source of packet information for scheduler, DEFAULT = pcap_data/browse2.pcap\n");
}

int parse_number(char *s, long *value)
{
    char *endptr;
    long val = strtol(s, &endptr, 10);
    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
        || (errno != 0 && val == 0)) {
        perror("strtol");
        return -1;
    }

    if (endptr == s) {
        fprintf(stderr, "No digits were found\n");
        return -1;
    }
    
    *value = val;
    return 0;
}

int main(int argc, char *argv[])
{
    const char *optstring = "s:c:b:i:t:g";
    int mode = '\0';
    int opt;
    char *arg_file4compare = NULL;
    char *arg_source = "pcap_data/browse2.pcap";
    char *arg_bandwidth = BW_PER_SEC;
    char *arg_pkt_interval = MAX_INTERVAL;
    char *arg_target_ip = MS_IP;

    long bandwidth;
    long max_interval;
    
    tfc_t *headt;

    /* Read command line options */
    /* ------------------------- */
    if (argc <= 1) {
        usage();
        exit(1);
    }

    while ((opt = getopt(argc, argv, optstring)) != -1) {
        switch (opt) {
            case 'c':
            if (mode != '\0') {
                printf("-c cannot be used with other mode at the same time.\n");
                exit(1);
            } else {
                mode = 'c';
            }
            arg_file4compare = optarg;
            break;
            
            case 'g':
            if (mode != '\0') {
                printf("-g cannot be used with other mode at the same time.\n");
                exit(1);
            } else {
                mode = 'g';
            }
            break;
            
            case 's':
            arg_source = optarg;
            break;
            
            case 'b':
            arg_bandwidth = optarg;
            break;

            case 'i':
            arg_pkt_interval = optarg;
            break;

            case 't':
            arg_target_ip = optarg;
            break;
        }
    }
#ifdef DEBUG
    printf("c=%s, b=%s, i=%s, s=%s, t=%s\n", 
            arg_file4compare, arg_bandwidth, 
            arg_pkt_interval, arg_source, arg_target_ip);
#endif
    if (parse_number(arg_bandwidth, &bandwidth) == -1 
        || parse_number(arg_pkt_interval, &max_interval) == -1
        || arg_source == NULL
        || arg_target_ip == NULL
        || (mode == 'c' && arg_file4compare == NULL)) {
        usage();
        exit(1);    
    }

    headt = build_traffic_pcap(arg_source, arg_target_ip);
    if (headt == NULL) {
        fprintf(stderr, "build_traffic_pcap failed\n");
        exit(1);
    }
    schedule(headt, bandwidth, max_interval);

    if (mode == 'g')
        /*  Transfer sharped pkt information to the kernel module */
        sync_traffic_data(headt);
    else if (mode == 'c')
        /* Compare results */
        result_compare(headt, arg_file4compare);
    
    return 0;
}
