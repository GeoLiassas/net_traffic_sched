#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <stdlib.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "scheduler.h"

/* This is a traffic source adapter for PCAP file.
 * The adapter will read PCAP file, and build up
 * traffic information required by scheduler.
 */

#define ptime(tvptr) \
    printf("%ld.%06ld\n", (tvptr)->tv_sec, (tvptr)->tv_usec)


tfc_t *build_traffic_pcap(char *, char *);

int replay_pcap(char *, char *);

int result_compare(tfc_t *, char *);

static int rawfd;


static unsigned int 
send_pkt(int fd, void *data, int len, 
            struct sockaddr_in *dst, struct timeval *delay)
{
    struct timeval local_copy;
    int n;
    
    /* The slect call might change the value of struct timeval,
     * so we do a copy here, and also modify the timeval if 
     * tv_usec is a negative number.
     */
    memcpy(&local_copy, delay, sizeof(struct timeval));
    if (local_copy.tv_usec < 0) {
        local_copy.tv_sec--;
        local_copy.tv_usec += 1000000;
    }
    printf("send_pkt: delaytime: ");
    ptime(&local_copy);
    /* Using select call to achieve packet delay */
    if((n = select(0, NULL, NULL, NULL, &local_copy)) == -1)
        perror("send_pkt: select");
    
    if((n = sendto(fd, data, len, 0, (void *) dst, 
                        sizeof(struct sockaddr))) == -1)
        perror("send_pkt: sendto");
    return n;
}

tfc_t *build_traffic_pcap(char *fpath, char *target_ip)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    u_char *p;
    struct ether_header *eth_hdr;
    struct ip *ip_hdr;
    
    unsigned int pkt_counter = 0;
    struct sockaddr_in msaddr;
    tfc_t *headt, *tp;

    headt = (tfc_t *) malloc(sizeof(tfc_t));
    if (headt == NULL) {
        perror("build_traffic_pcap: malloc");
    }
    dclist_init_head(&headt->list);

    memset(&msaddr, 0, sizeof(struct sockaddr_in));
    msaddr.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip, &msaddr.sin_addr);
    
    handle = pcap_open_offline(fpath, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open pcap file %s: %s\n", fpath, errbuf);
        return NULL;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        p = (u_char *) packet;
        eth_hdr = (struct ether_header *) packet;
        if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
            ip_hdr = (struct ip *)(p + sizeof(struct ether_header));
            if (msaddr.sin_addr.s_addr == ip_hdr->ip_dst.s_addr) {
                pkt_counter++;
                tp = (tfc_t *) malloc(sizeof(tfc_t));
                if (tp == NULL) {
                    perror("build_traffic_pcap: malloc");
                }
                tp->size = ntohs(ip_hdr->ip_len);
                tp->time = header.ts.tv_sec*1000 + header.ts.tv_usec/1000;
                tp->pkt = NULL;
                tp->priority = 1;
                dclist_add(&tp->list, &headt->list);
            }
        }
 
    }
    return headt;
}


int replay_pcap(char *fpath, char *target_ip)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    struct timeval prev_time, time_diff;

    const u_char *packet;
    u_char *p;
    struct ether_header *eth_hdr;
    struct ip *ip_hdr;

    int eth_proto, n;
    struct sockaddr_in sendto_addr;
    
    int count = 0;

    memset(&time_diff, 0, sizeof(struct timeval));
    memset(&prev_time, 0, sizeof(struct timeval));

    memset(&sendto_addr, 0, sizeof(struct sockaddr_in));
    sendto_addr.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip, &sendto_addr.sin_addr);

    if ((rawfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        perror("repay_pcap: socket");
        exit(1);
    }
    if ((handle = pcap_open_offline(fpath, errbuf)) == NULL) {
        fprintf(stderr, "Couldn't open pcap file %s: %s\n", fpath, errbuf);
        return -1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        p = (u_char *) packet;
        printf("%d|", count++);
        ptime(&header.ts);
        eth_hdr = (struct ether_header *) p;
        if((eth_proto = ntohs(eth_hdr->ether_type)) == ETHERTYPE_IP)
        {
            ip_hdr = (struct ip *)(p + sizeof(struct ether_header));
#ifdef DEBUG
            printf("%02X:%02X:%02X:%02X:%02X:%02X > %02X:%02X:%02X:%02X:%02X:%02X, "
                   "proto = %04X\n",
                    p[0], p[1], p[2], p[3], p[4], p[5],
                    p[6], p[7], p[8], p[9], p[10], p[11],
                    eth_proto);
        
        
            p = (u_char *)&(ip_hdr->ip_src.s_addr);
            printf("%u.%u.%u.%u > %u.%u.%u.%u, proto = %02X\n",
                    p[0], p[1], p[2], p[3],
                    p[4], p[5], p[6], p[7],
                    ip_hdr->ip_p);
#endif
            if (sendto_addr.sin_addr.s_addr == ip_hdr->ip_dst.s_addr) {
                if (prev_time.tv_sec == prev_time.tv_usec && prev_time.tv_usec == 0) {
                    time_diff.tv_sec = time_diff.tv_usec = 0;
                } else {
                    time_diff.tv_sec = header.ts.tv_sec - prev_time.tv_sec;
                    time_diff.tv_usec = header.ts.tv_usec - prev_time.tv_usec;
                }
                memcpy(&prev_time, &header.ts, sizeof(struct timeval));
                n = send_pkt(rawfd, ip_hdr, ntohs(ip_hdr->ip_len), 
                                &sendto_addr, &time_diff);
                printf("Sent: %d\n", n);
            }
        }
    }
    pcap_close(handle);
    
    return 0;
}

int result_compare(tfc_t *estimation, char *sharped_pcap)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    u_char *p;
    struct ether_header *eth_hdr;
    struct ip *ip_hdr;


    struct lnode *ln;
    tfc_t *tp;

    unsigned long long est_prev;
    unsigned long long sharped_prev;
    long est_diff;
    long sharped_diff;
    char *flag;

    int idx = 0;

    handle = pcap_open_offline(sharped_pcap, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open pcap file %s: %s\n", sharped_pcap, errbuf);
        return -1;
    }


    dclist_foreach(ln, &estimation->list) {
        flag = "";
        if ((packet = pcap_next(handle, &header)) == NULL) break;
        p = (u_char *) packet;
        
        tp = dclist_outer(ln, tfc_t, list);
        
        eth_hdr = (struct ether_header *) packet;
        if((ntohs(eth_hdr->ether_type)) == ETHERTYPE_IP)
        {
            ip_hdr = (struct ip *)(p + sizeof(struct ether_header));
            if (ntohs(ip_hdr->ip_len) == tp->size)
                flag = "M";
        }
 
        
        if (idx++ == 0) {
            est_prev = tp->time;
            sharped_prev = header.ts.tv_sec * 1000 + header.ts.tv_usec / 1000;
        }
        
        est_diff = tp->time - est_prev;
        sharped_diff = (header.ts.tv_sec*1000 + header.ts.tv_usec/1000) 
                                                            - sharped_prev;
        printf("%8d - Estimated: %-10ld  Actual: %-10ld   Diff: %5ld  Flag: %s\n", 
                    idx, est_diff, sharped_diff, est_diff - sharped_diff, flag);
        
        est_prev = tp->time;
        sharped_prev = header.ts.tv_sec * 1000 + header.ts.tv_usec / 1000;
    }
    return 0;
}
 
