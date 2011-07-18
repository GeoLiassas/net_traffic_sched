#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

extern int replay_pcap(char *, char *);

void usage()
{
    printf("Usage of replay_pcap: \n");
    printf("   ./replay_pcap -t TARGET_IP -s PACKET_SOURCE\n");

    printf("\nOptions: \n");
    printf("   -t IP of the target mobible station, example:192.168.10.10\n");
    printf("   -s Source of packet information for scheduler, example:pcap_data/browse2.pcap\n");
}

int main (int argc, char *argv[])
{
    const char *optstring = "t:s:";
    int opt;
    char *pcap_file = NULL;
    char *target_ip = NULL;

    /* Read command line options */
    /* ------------------------- */
    if (argc != 5) {
        usage();
        exit(1);
    }

    while ((opt = getopt(argc, argv, optstring)) != -1) {
        switch (opt) {
            case 't':
            target_ip = optarg;
            break;

            case 's':
            pcap_file = optarg;
            break;
        }
    }
    if (target_ip == NULL || pcap_file == NULL) {
        usage();
        exit(1);
    }

    /* Start to replay pcap file */
    replay_pcap(pcap_file, target_ip);
    return 0;
}
