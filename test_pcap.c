extern int build_traffic_pcap(char *); 
extern int replay_pcap(char *);
int main ()
{
    replay_pcap("pcap_data/browse2.pcap");
    return 0;
}
