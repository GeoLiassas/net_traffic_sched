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

tfc_t *build_traffic_pcap(char *, char *);

int replay_pcap(char *, char *);

int result_compare(tfc_t *, char *);

/**
 * The file descriptor of raw socket, which is internally used for
 * replay the pcap file.
 */
static int rawfd;

/**
 * Sending a packet via raw socket with delays. This is a wrap
 * function of sendto in socket API, and provides possibility of
 * delay a packet for a specific period before send it out.
 */
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

#ifdef DEBUG
    printf("send_pkt: delaytime: ");
    ptime(&local_copy);
#endif

    /* Using select call to achieve packet delay */
    if((n = select(0, NULL, NULL, NULL, &local_copy)) == -1)
        perror("send_pkt: select");
    /* Send packet */
    if((n = sendto(fd, data, len, 0, (void *) dst, 
                        sizeof(struct sockaddr))) == -1)
        perror("send_pkt: sendto");
    return n;
}

/**
 * Build traffic_data list from pcap file, and it only selects
 * IP packets with specified destination IP address.
 *
 * @fpath The file path of the pcap file.
 * @target_ip The destination IP address.
 */
tfc_t *build_traffic_pcap(char *fpath, char *target_ip)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    u_char *p;
    struct ether_header *eth_hdr;
    struct ip *ip_hdr;
    
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
                tp = (tfc_t *) malloc(sizeof(tfc_t));
                if (tp == NULL) {
                    perror("build_traffic_pcap: malloc");
                }
                tp->size = ntohs(ip_hdr->ip_len);
                tp->otime = header.ts.tv_sec*1000 + header.ts.tv_usec/1000;
                tp->time = header.ts.tv_sec*1000 + header.ts.tv_usec/1000;
                tp->pkt = NULL;
                tp->priority = 1;
                /* !!Use IP header checksum as packet identifier. */
                tp->id = get_pkt_id(ip_hdr);
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

                p = (u_char *)&(ip_hdr->ip_src.s_addr);
                printf("%6d|%3u.%3u.%3u.%3u > %3u.%3u.%3u.%3u [%08X], %5d bytes\n",
                        count++,
                        p[0], p[1], p[2], p[3],
                        p[4], p[5], p[6], p[7],
                        (unsigned int)get_pkt_id(ip_hdr), n);
            }
        }
    }
    pcap_close(handle);
    
    return 0;
}

struct pcap_pkt_info {
    unsigned long id;
    struct pcap_pkthdr header;
    struct lnode list;
};

static int
read_pcap_info(char *pcap_file, struct pcap_pkt_info *linkhead)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    u_char *p;
    struct ether_header *eth_hdr;
    struct ip *ip_hdr;
    struct pcap_pkt_info *pkt_info;
    struct pcap_pkthdr header;

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open pcap file %s: %s\n", pcap_file, errbuf);
        return -1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        p = (u_char *)packet;
        eth_hdr = (struct ether_header *) packet;

        if ((ntohs(eth_hdr->ether_type)) == ETHERTYPE_IP) {
            ip_hdr = (struct ip *) (p + sizeof(struct ether_header));
            pkt_info = (struct pcap_pkt_info *) 
                        malloc(sizeof(struct pcap_pkt_info));
            if (pkt_info == NULL) {
                perror("read_pcap_info: malloc");
                return -1;
            }
            memset(pkt_info, 0, sizeof(struct pcap_pkt_info));

            pkt_info->id = get_pkt_id(ip_hdr);
            memcpy(&pkt_info->header, &header, sizeof(struct pcap_pkthdr));
            dclist_r_add(&pkt_info->list, &linkhead->list);
        } else {
            continue;
        }
    }
    pcap_close(handle);
    return 0;

}

//TODO optimization. This is a helper function of result_compare().
static int
match_result_pkt(struct pcap_pkt_info *linkhead, unsigned long id, struct pcap_pkthdr *header)
{
    struct lnode *ln;
    struct pcap_pkt_info *info;

    dclist_foreach(ln, &linkhead->list) {
        info = dclist_outer(ln, struct pcap_pkt_info, list);
        if (info->id == id) {
            memcpy(header, &info->header, sizeof(struct pcap_pkthdr));
            return 1;
        }
    }
    return 0;
}


int result_compare(tfc_t *estimation, char *sharped_pcap)
{
    struct lnode *ln;
    tfc_t *tp;
    struct pcap_pkthdr header;
    struct pcap_pkt_info info_head = {
        .list = {&info_head.list, &info_head.list},
    };

    unsigned long long est_prev = -1;
    unsigned long long sharped_prev = -1;
    long est_diff;
    long sharped_diff;
    int idx = 0;
    int res;

    if (read_pcap_info(sharped_pcap, &info_head) == -1) {
        fprintf(stderr, "read_pcap_info failed\n");
        return -1;
    }

    dclist_foreach(ln, &estimation->list) {
        tp = dclist_outer(ln, tfc_t, list);
        if ((res = match_result_pkt(&info_head, tp->id, &header)) == -1) {
            fprintf(stderr, "match_result_pkt failed\n");
            return -1;
        }

        if (est_prev == -1)
            est_prev = tp->time;
        est_diff = tp->time - est_prev;

        if (res != 0) {
            if (sharped_prev == -1)
                sharped_prev = tv2ms(&header.ts);
            sharped_diff = tv2ms(&header.ts) - sharped_prev;

            //print matched line
            printf("%05d-%08X - Estimated: %-10ld  Actual: %-10ld  Diff: %5ld  Flag: M\n",
                        idx,
                        (unsigned int)tp->id, 
                        est_diff, 
                        sharped_diff, 
                        est_diff - sharped_diff);

            sharped_prev = tv2ms(&header.ts);
        } else {
            //print unmatched line
            printf("%05d-%08X - Estimated: %-10ld  Actual: %-10s  Diff: %5s  Flag:   \n", 
                    idx,
                    (unsigned int)tp->id,
                    est_diff,
                    "---",
                    "---");
        }

        est_prev = tp->time;
        idx++;
    }

    return 0;
}
 
