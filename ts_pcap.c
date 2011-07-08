#include <stdio.h>
#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>

/* This is a traffic source adapter for PCAP file.
 * The adapter will read PCAP file, and build up
 * traffic information required by scheduler.
 */
int build_traffic_pcap(char *);


int build_traffic_pcap(char *fpath)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    struct ether_header *eth_hdr;
    struct ip *ip_hdr;

    unsigned int pkt_count = 0;

    int eth_proto;

    handle = pcap_open_offline(fpath, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open pcap file %s: %s\n", fpath, errbuf);
        return -1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        u_char *p = (u_char *) packet;

        pkt_count++;
        printf("%ld.%06ld\n", header.ts.tv_sec, header.ts.tv_usec);
        eth_hdr = (struct ether_header *) p;
        eth_proto = ntohs(eth_hdr->ether_type);
        printf("%02X:%02X:%02X:%02X:%02X:%02X > %02X:%02X:%02X:%02X:%02X:%02X, proto = %04X\n",
                p[0], p[1], p[2], p[3], p[4], p[5],
                p[6], p[7], p[8], p[9], p[10], p[11],
                eth_proto);
        ip_hdr = (struct ip *)(p + sizeof(struct ether_header));
        p = (u_char *)&(ip_hdr->ip_src.s_addr);
        printf("%u.%u.%u.%u > %u.%u.%u.%u, proto = %02X\n",
                p[0], p[1], p[2], p[3],
                p[4], p[5], p[6], p[7],
                ip_hdr->ip_p);
    }
    pcap_close(handle);
    
    printf("---Total: %u\n", pkt_count);
}
 
