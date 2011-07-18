#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/ip.h>

#include <net/netfilter/nf_queue.h>
#include <linux/proc_fs.h>

#include "../scheduler.h"

/*
 * k_flow_control: Kernel flow control
 * ===================================
 */

/* module parameters */
static u32 subnet   = 0xC0A80A00; //192.168.10.0 TODO hardcoded
static u32 netmask  = 0xFFFFFF00; //255.255.255.0 TODO hardcoded
static u32 TARGET_IP = 0xC0A80A01; //192.168.10.1 TODO hardcoded
static tfc_t headt = {
    .list = {&headt.list, &headt.list},
};

static int flow_control = 0;
static tfc_t *fcp;

#define CMD_FLOW_CONTROL 723

/* Proc related */
#define PROC_DIR            "sch_80211"
#define PROC_F_PREDICTION   "prediction"
#define PROC_PERMS          0644



static struct proc_dir_entry *proc_dir, *prediction_file;

static int procfs_open(struct inode *inode, struct file* file)
{
    try_module_get(THIS_MODULE);
    return 0;
}

static int procfs_close(struct inode *inode, struct file *file)
{
    module_put(THIS_MODULE);
    return 0;
}

static ssize_t
write_prediction(struct file *file, 
                 const char *buffer, 
                 size_t len, 
                 loff_t *off)
{
    const int BUF_SIZE = 512;
    char procfs_buffer[BUF_SIZE];
    unsigned long procfs_buffer_size = 0;

    unsigned long long time;
    unsigned int size;
    int priority;
    int cmd_code;
    int n, count;
    tfc_t *tp;
    struct lnode *ln;

    printk(KERN_INFO "@write::buffer_length = %lu, offset=%lld\n", len, *off);
    if (len > BUF_SIZE) {
        procfs_buffer_size = BUF_SIZE;
    }
    else {
        procfs_buffer_size = len;
    }

    if (copy_from_user(procfs_buffer, buffer, procfs_buffer_size)) {
        return -EFAULT;
    }
    n = sscanf(procfs_buffer, "%llu %u %d", &time, &size, &priority);
    if (n == 3){
        printk(KERN_INFO "%llu\t%u\t%d\n", time, size, priority);
        tp = (tfc_t *) kmalloc(sizeof(tfc_t), GFP_KERNEL);
        tp->time = time;
        tp->size = size;
        tp->priority = priority;
        dclist_add(&tp->list, &headt.list);
    } else {
        n = sscanf(procfs_buffer, "%d", &cmd_code);
        if (n == 1) {
            switch(cmd_code) {
                case CMD_FLOW_CONTROL:
                    fcp = &headt;
                    flow_control = 1;
                    count = 0;
                    dclist_foreach(ln, &headt.list) {
                        tp = dclist_outer(ln, tfc_t, list);
                        printk(KERN_INFO "|%llu  %u  %d\n", 
                                            tp->time, tp->size, tp->priority);
                        count++;
                    }
                    printk(KERN_INFO "%d receiverd, flow_control open\n", count);
                break;
            }
        }
    }
    
    return procfs_buffer_size;
}

//FIXME what should be provided through this reading function?
static ssize_t read_prediction(struct file *filp, /* see include/linux/fs.h   */
                               char *buffer,      /* buffer to fill with data */
                               size_t length,     /* length of the buffer     */
                               loff_t * offset)
{   
    /*
    static int finished = 0;

    printk(KERN_INFO "@read::buffer_length = %lu\n", length);
    if (finished) {
            printk(KERN_INFO "procfs_read: END\n");
            finished = 0;
            return 0;
    }
    
    finished = 1;
            
    if (copy_to_user(buffer, procfs_buffer, procfs_buffer_size)) {
            return -EFAULT;
    }

    printk(KERN_INFO "procfs_read: read %lu bytes\n", procfs_buffer_size);

    return procfs_buffer_size;
    */
    return 0;
 }

static struct file_operations prediction_ops = {
    .read     = read_prediction,
    .write    = write_prediction,
    .open     = procfs_open,
    .release  = procfs_close,
};

/* head of the list of the nf_queue */
static struct nf_queue_entry head_entry = { 
    .list = LIST_HEAD_INIT(head_entry.list)
};

static unsigned int entry_id = 1;

static unsigned int
traffic_sharp(unsigned int hook,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *skb))
{
    struct iphdr *iph = ip_hdr(skb);

    if (ntohl(iph->daddr) == TARGET_IP && flow_control) {
        printk(KERN_INFO "::FC::%pI4 > %pI4\n", &iph->saddr, &iph->daddr);
        fcp = dclist_outer(fcp->list.next, tfc_t, list);
        if (fcp == &headt) {
            flow_control = 0;
            printk(KERN_INFO "::::::flow_control closed\n"); 
            return NF_ACCEPT;
        }
        printk(KERN_INFO "::::::QUEUE:%llu  %u  %d\n", 
                            fcp->time, fcp->size, fcp->priority);
        return NF_QUEUE;
    } else {
        return NF_ACCEPT;
    }
}

static int
queue_callback(struct nf_queue_entry *entry, 
                unsigned int queuenum) 
{
    struct nf_queue_entry *q, *qnext;
    int reinject_pkts = 0;
    tfc_t *tfc_next;

    entry->id = entry_id++;
    printk(KERN_INFO "::::::ID in queue: %d\n", entry->id);
    list_add_tail(&entry->list, &head_entry.list);

    tfc_next = dclist_outer(fcp->list.next, tfc_t, list);
    if (tfc_next != &headt && (tfc_next->time - fcp->time) > 5)
        reinject_pkts = 1;

    if (tfc_next == &headt)
        reinject_pkts = 1;

    if (reinject_pkts) {
        list_for_each_entry_safe(q, qnext, &head_entry.list, list) {
            printk(KERN_INFO "::::::Reinject: %d\n", q->id);
            nf_reinject(q, NF_ACCEPT);
        }
        INIT_LIST_HEAD(&head_entry.list);
        reinject_pkts = 0;
    }
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
    /* Register NF hook */
    ret = nf_register_hook(&pkt_ops);
    if (ret < 0 ) {
        printk(KERN_INFO "Fail to register NF hook: %d\n", ret);
        return -1;
    }
    /* Register NF_queue handler */
    ret = nf_register_queue_handler(PF_INET, &queuehandler);
    if (ret < 0) {
        printk(KERN_INFO "Reg queue failed with %d\n", ret);
        return -1;
    }
    /* Setup proc */
    proc_dir = proc_mkdir(PROC_DIR, NULL);
    if (proc_dir == NULL)
        return -ENOMEM;

    prediction_file = create_proc_entry(PROC_F_PREDICTION, 
                                         PROC_PERMS, proc_dir);
    if (prediction_file == NULL) {
        remove_proc_entry(PROC_DIR, NULL);
        return -ENOMEM;
    }
    prediction_file->proc_fops = &prediction_ops;
    prediction_file->mode = S_IFREG | S_IRUGO | S_IWUSR;
    prediction_file->uid = 0;
    prediction_file->gid = 0;
    prediction_file->size = 80;

    return 0;
}

static void __exit pkts_exit(void) {
    tfc_t *tp;
    struct lnode *ln, *ltemp;
    nf_unregister_queue_handlers(&queuehandler);
    nf_unregister_hook(&pkt_ops);
    
    remove_proc_entry(PROC_F_PREDICTION, proc_dir);
    remove_proc_entry(PROC_DIR, NULL);

    /* free memory */
    dclist_foreach_safe(ln, ltemp, &headt.list) {
        tp = dclist_outer(ln, tfc_t, list);
        kfree(tp);
    }
    printk(KERN_INFO "pkt_scheduler ends\n");
}

module_init(pkts_init);
module_exit(pkts_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("sharp traffic for wireless station");

