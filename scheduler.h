#ifndef SCHEDULER_H
#define SCHEDULER_H
#include "dclist.h"

//#define DEBUG

typedef struct traffic_data {
    unsigned long long otime;       /* original time, in millisecond */
    unsigned long long time;        /* scheduled time, in millisecond */
    unsigned int size;              /* Size of the packet */
    int priority;                   /* Priority of the packet */
    struct lnode list;              /* Internel list structure */
    unsigned long id;               /* Identity of this packet */
    unsigned char *pkt;
} tfc_t;


/**
 * Schedule fuction, accepting a list of trafic data, and re-arranging
 * the sending time for each of them in order to achieve bursting.
 */
int sch_schedule(tfc_t*, long, long);

#define tv2ms(tv) \
    ((tv)->tv_sec * 1000 + (tv)->tv_usec / 1000)

#define ptime(tvptr) \
    printf("%ld.%06ld\n", (tvptr)->tv_sec, (tvptr)->tv_usec)


#ifndef __KERNEL__
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
static inline unsigned long
get_pkt_id(struct ip *ip_hdr) {
    unsigned long id;
    unsigned long temp;
    struct tcphdr *tcph;
    struct udphdr *udph;

    id = ip_hdr->ip_sum;
    switch(ip_hdr->ip_p) {
        case 0x06: //tcp
            tcph = (struct tcphdr*)(((char *) ip_hdr) + ip_hdr->ip_hl * 4);
            temp = tcph->check;
            id = (temp << 16) + id;
            break;
        case 0x11: //udp
            udph = (struct udphdr*)(((char *) ip_hdr) + ip_hdr->ip_hl * 4);
            temp = udph->check;
            id = (temp << 16) + id;
            break;
    }
    
    return id;
}
#endif

#ifdef __KERNEL__
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
static inline unsigned long
get_pkt_id(struct iphdr * ip_hdr) {
    unsigned long id;
    unsigned long temp;
    struct tcphdr *tcph;
    struct udphdr *udph;

    id = ip_hdr->check;
    switch(ip_hdr->protocol) {
        case 0x06: //tcp
            tcph = (struct tcphdr*)(((char *) ip_hdr) + ip_hdr->ihl * 4);
            temp = tcph->check;
            id = (temp << 16) + id;
            break;
        case 0x11: //udp
            udph = (struct udphdr*)(((char *) ip_hdr) + ip_hdr->ihl * 4);
            temp = udph->check;
            id = (temp << 16) + id;
            break;
    }
    
    return id;

}
#endif

#define MS_IP "192.168.10.1"
#endif

