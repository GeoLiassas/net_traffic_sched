#include <stdio.h>
#include <string.h>
#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

/* This is a traffic source adapter for PCAP file.
 * The adapter will read PCAP file, and build up
 * traffic information required by scheduler.
 */

#define ptime(tvptr) \
    printf("%ld.%06ld\n", (tvptr)->tv_sec, (tvptr)->tv_usec)


int build_traffic_pcap(char *);

int rawfd;


unsigned int 
send_pkt(int fd, void *data, int len, 
            struct sockaddr_in *dst, struct timeval *delay)
{
    struct timeval local_copy;
    int n;
    
    printf("send_pkt: ");
    ptime(delay);
    printf("\n");
    memcpy(&local_copy, delay, sizeof(struct timeval));
    if((n = select(0, NULL, NULL, NULL, &local_copy)) == -1)
        perror("send_pkt: select");
    
    if((n = sendto(fd, data, len, 0, (void *) dst, 
                        sizeof(struct sockaddr))) == -1)
        perror("send_pkt: sendto");
    return n;
}


int build_traffic_pcap(char *fpath)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    struct timeval prev_time;
    struct timeval time_diff;
    struct pcap_pkthdr *pcap_ptr = NULL;

    const u_char *packet;
    struct ether_header *eth_hdr;
    struct ip *ip_hdr;

    unsigned int pkt_count = 0;

    int eth_proto;
    int send_res;
    struct sockaddr_in sendto_addr;

    int temp_counter = 200;

    memset(&time_diff, 0, sizeof(struct timeval));
    memset(&prev_time, 0, sizeof(struct timeval));

    memset(&sendto_addr, 0, sizeof(struct sockaddr_in));
    sendto_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.10.1", &sendto_addr.sin_addr);
    

    rawfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    handle = pcap_open_offline(fpath, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open pcap file %s: %s\n", fpath, errbuf);
        return -1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL && temp_counter--) {
        u_char *p = (u_char *) packet;

        pkt_count++;
        ptime(&header.ts);
        eth_hdr = (struct ether_header *) p;
        if((eth_proto = ntohs(eth_hdr->ether_type)) == ETHERTYPE_IP)
        {
            printf("%02X:%02X:%02X:%02X:%02X:%02X > %02X:%02X:%02X:%02X:%02X:%02X,proto = %04X\n",
                    p[0], p[1], p[2], p[3], p[4], p[5],
                    p[6], p[7], p[8], p[9], p[10], p[11],
                    eth_proto);
            ip_hdr = (struct ip *)(p + sizeof(struct ether_header));
            p = (u_char *)&(ip_hdr->ip_src.s_addr);
            printf("%u.%u.%u.%u > %u.%u.%u.%u, proto = %02X\n",
                    p[0], p[1], p[2], p[3],
                    p[4], p[5], p[6], p[7],
                    ip_hdr->ip_p);
            if (sendto_addr.sin_addr.s_addr == ip_hdr->ip_dst.s_addr) {
                if (prev_time.tv_sec == prev_time.tv_usec && prev_time.tv_usec == 0) {
                    time_diff.tv_sec = time_diff.tv_usec = 0;
                } else {
                    time_diff.tv_sec = header.ts.tv_sec - prev_time.tv_sec;
                    time_diff.tv_usec = header.ts.tv_usec - prev_time.tv_usec;
                }
                memcpy(&prev_time, &header.ts, sizeof(struct timeval));
                send_res = send_pkt(rawfd, ip_hdr, ntohs(ip_hdr->ip_len), 
                                &sendto_addr, &time_diff);
                printf("Sent: %d\n", send_res);
            }
        }
    }
    pcap_close(handle);
    
    printf("---Total: %u\n", pkt_count);
    return 0;
}
 
