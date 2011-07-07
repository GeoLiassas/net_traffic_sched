#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/ip.h>

#include <net/netfilter/nf_queue.h>

static u32 subnet = 0xC0A80A00; //192.168.10.0
static u32 netmask= 0xFFFFFF00; //255.255.255.0

//static int 
//queue_callback(struct sk_buff *, struct nf_info *, unsigned int, void *);

static unsigned int
traffic_sharp(unsigned int hook,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *skb))
{
    struct iphdr *iph = ip_hdr(skb);

    printk(KERN_INFO "::::%pI4 > %pI4", &iph->saddr, &iph->daddr);
    printk(KERN_INFO "%8x\n", iph->daddr);
    printk(KERN_INFO "%8x\n", netmask);
    printk(KERN_INFO "%8x\n", (iph->daddr & netmask));
    if ((ntohl(iph->daddr) & netmask) == subnet) {
        printk(KERN_INFO "NF_QUEUE!\n");
        return NF_QUEUE;
    } else {
        return NF_ACCEPT;
    }
}

static int
queue_callback(struct nf_queue_entry *entry, 
                unsigned int queuenum) 
{
    printk(KERN_INFO "****Q HANDLER CALLED, Reinject pkt****\n");
    nf_reinject(entry, NF_ACCEPT);
    return 1;
}

static struct nf_hook_ops pkt_ops = {
    .hook = traffic_sharp,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = -1
};

static struct nf_queue_handler queuehandler = {
    .name = "TrafficSchedulerQueue",
    .outfn = &queue_callback
};

static int __init pkts_init(void) {
    int ret;

    printk(KERN_INFO "pkt_scheduler starts\n");
    ret = nf_register_hook(&pkt_ops);

    ret = nf_register_queue_handler(PF_INET, &queuehandler);
    if (ret < 0) {
        printk(KERN_INFO "Reg queue failed with %d\n", ret);
        return -1;
    }
    return 0;
}

static void __exit pkts_exit(void) {
    printk(KERN_INFO "pkt_scheduler ends\n");
    nf_unregister_queue_handlers(&queuehandler);
    nf_unregister_hook(&pkt_ops);
}

module_init(pkts_init);
module_exit(pkts_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("sharp traffic for wireless station");

