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

#include <asm/div64.h>
/*
 * k_flow_control: Kernel flow control
 * ===================================
 */

/* module parameters */
static u32 target_ip = 0;
static char *target = "192.168.10.101";
module_param(target, charp, S_IRUGO);
MODULE_PARM_DESC(target, 
                  "The IP of Mobile station for traffic sharping");

/**
 *Record the head of the traffic data.
 */
static tfc_t headt = {
    .list = {&headt.list, &headt.list},
};

/**
 * Flow control flag.
 */
static int flow_control = 0;

/**
 * Flow control pointer, which points to current traffic data.
 */
static tfc_t *fcp = &headt;

/**
 * The time difference between original arrival time and current arrival
 * time, since we replay a traffic file, the current arrival time should
 * be largger than the original one.
 */
static unsigned long long time_shift = 0;
/**
 * Queue lookup pointer 
 */
static tfc_t *qlp = &headt;


/**
 * Utility function, convert string format of IP to 32 bit unsigned.
 */
static inline u32 
k_v4pton(char *ipv4)
{
    u32 ip;
    unsigned char *p = (unsigned char *) &ip;
    if((sscanf(ipv4, "%hhu.%hhu.%hhu.%hhu", p, p+1, p+2, p+3)) != 4)
        return 0;
    return ip;
}

/**
 * Utility function, calculate time_shift from a given traffic data.
 */
static inline unsigned long long 
cal_timeshift(tfc_t * tp)
{
    struct timeval now;
    do_gettimeofday(&now);
    
    return tv2ms(&now) - tp->otime;
}

/**
 * Utility function, shift a given time according to the given time delta.
 */
static inline unsigned long long
shift_time(unsigned long long time, unsigned long long delta)
{
    return time + delta;
}

static int
time_shift_passed(unsigned long long time, unsigned long long delta)
{
    struct timeval now;
    do_gettimeofday(&now);
    
    return (shift_time(time, delta) <= tv2ms(&now));
}

/**
 * Proc command code
 * This command tells the kernel to stop accepting traffic data and
 * start the actual packet delaying.
 */
#define CMD_FLOW_CONTROL 723


/* Proc related
   ========================================================================= */
#define PROC_DIR            "sch_80211"
#define PROC_F_PREDICTION   "prediction"
#define PROC_PERMS          0644


/**
 * Proc folder and file under this folder
 */
static struct proc_dir_entry *proc_dir, *prediction_file;

/**
 * The Proc file operation: open
 * Simply increase the reference count
 */
static int procfs_open(struct inode *inode, struct file* file)
{
    try_module_get(THIS_MODULE);
    return 0;
}

/**
 * The Proc file operation: close
 * Decrease the reference count
 */
static int procfs_close(struct inode *inode, struct file *file)
{
    module_put(THIS_MODULE);
    return 0;
}

/**
 * The Proc file operation: write
 * This write function enables user to input traffic data from the user space
 * to the kernel. The traffic data format is "%llu %u %d", which stands for 
 * packet sending time, packet size (in bytes) and packet priority respectively.
 * Multiple packets should be handled one by one.
 *
 * This function also allow user to tell the kernel that all traffic data have
 * been sent and flow control can start to go. This functionality is implemented
 * by write different command code (an integer number) to this file.
 * Refer to macros start with "CMD_".
 */
static ssize_t
write_prediction(struct file *file, 
                 const char *buffer, 
                 size_t len, 
                 loff_t *off)
{
    const int BUF_SIZE = 512;
    char procfs_buffer[BUF_SIZE];
    unsigned long procfs_buffer_size = 0;

    unsigned long id;
    unsigned long long time;
    unsigned long long otime;
    unsigned int size;
    int priority;
    int cmd_code;
    int n, count;
    tfc_t *tp;
    struct lnode *ln;

    if (len > BUF_SIZE) {
        procfs_buffer_size = BUF_SIZE;
    }
    else {
        procfs_buffer_size = len;
    }

    if (copy_from_user(procfs_buffer, buffer, procfs_buffer_size)) {
        return -EFAULT;
    }
    n = sscanf(procfs_buffer, "%lu %llu %llu %u %d", &id, &otime, &time, &size, &priority);
    if (n == 5){
        tp = (tfc_t *) kmalloc(sizeof(tfc_t), GFP_KERNEL);
        tp->id = id;
        tp->otime = otime;
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
#ifdef DEBUG
                        printk(KERN_INFO "|%08X  %llu  %u  %d\n", 
                                         (unsigned int)tp->id, tp->time, 
                                         tp->size, tp->priority);
#endif
                        count++;
                    }
                    printk(KERN_INFO "%d receiverd, flow_control open\n", count);
                break;
            }
        }
    }
    
    return procfs_buffer_size;
}

/**
 * The Proc file operation: read
 * Currently this function is not needed.
 */
static ssize_t read_prediction(struct file *filp, 
                               char *buffer,
                               size_t length,     
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

/* Proc file operations */
static struct file_operations prediction_ops = {
    .read     = read_prediction,
    .write    = write_prediction,
    .open     = procfs_open,
    .release  = procfs_close,
};

/**
 * NF_HOOK
 =============================================================================*/

/**
 * NF_HOOK call back function
 * In this function, we queue all packets with destination to the target ip.
 * For other packets, we just accept them, without any changes.
 * The target ip a configable module paramter.
 */
static unsigned int
traffic_sharp(unsigned int hook,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *skb))
{
    struct iphdr *iph = ip_hdr(skb);
    tfc_t *tp = NULL;
    struct lnode *ln;

    if (iph->daddr == target_ip && flow_control) {
        printk(KERN_INFO "::FC::%pI4 > %pI4\n", &iph->saddr, &iph->daddr);

        dclist_foreach(ln, &fcp->list) {
            tp = dclist_outer(ln, tfc_t, list);
            if (tp->id == get_pkt_id(iph)) 
                break;
        }

        if (tp == &headt) {
            //If we run to here, it should be a bug.
            //NOT queue this packet
            printk(KERN_ERR "traffic_sharp, cannot match traffic data id\n");
            return NF_DROP;
        }

        fcp = tp;

        /* stop flow control if we finish the iteration */
        tp = dclist_outer(fcp->list.next, tfc_t, list);
        if (tp == &headt) {
            flow_control = 0;
            printk(KERN_INFO "::::::flow_control closed\n"); 
        }

        /* Queue the matched packet */
        printk(KERN_INFO "::::::QUEUE:[%08X]  %llu  %u  %d\n", 
                            (unsigned int)fcp->id, 
                            fcp->time, 
                            fcp->size, 
                            fcp->priority);
        return NF_QUEUE;
    } else {
        return NF_ACCEPT;
    }
}

/**
 * NF_HOOK registration information
 */
static struct nf_hook_ops pkt_ops = {
    .hook = traffic_sharp,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = -1
};

/**
 * NF_QUEUE
 ============================================================================*/
#define MAX_BURST_GAP 5

static unsigned int entry_id = 0;

/* head of the list of the nf_queue */
static struct nf_queue_entry head_entry = { 
    .list = LIST_HEAD_INIT(head_entry.list)
};

/* Queue call back function */
static int pkt_num_in_q = 0;
static int
queue_callback(struct nf_queue_entry *entry, 
                unsigned int queuenum) 
{
    struct iphdr *iph = ip_hdr(entry->skb);
    struct nf_queue_entry *q, *qnext;
    int reinject_pkts = 0; /* flag */
    tfc_t *tfc_curr, *tfc_next, *tp;

    entry->id = entry_id++;
    printk(KERN_INFO "::::::ID in queue: %d\n", entry->id);
    list_add_tail(&entry->list, &head_entry.list);
    
    for (;;) {
        tfc_curr = dclist_outer(qlp->list.next, tfc_t, list);
        if (tfc_curr == &headt || tfc_curr->id == get_pkt_id(iph))
            break;
    }

    if (tfc_curr == &headt) {
        //TODO it will be a bug if we run to here...
        printk(KERN_INFO "queue_callback, cannot match packet id\n");
        return 1;
    }
    //calculate time shift
    if (time_shift == 0)
        time_shift = cal_timeshift(tfc_curr);
    else {
	uint64_t temp = (time_shift * 7 + cal_timeshift(tfc_curr) * 3);
        time_shift =  do_div(temp, 10);
    }

    //determine if we should start to reinject packets.
    qlp = tfc_curr;
    tfc_next = dclist_outer(tfc_curr->list.next, tfc_t, list);
    if (tfc_next != &headt 
            && (tfc_next->time - tfc_curr->time) > MAX_BURST_GAP)
        reinject_pkts = 1;

    if (tfc_next == &headt)
        reinject_pkts = 1;

    if (++pkt_num_in_q >= 10) {
        printk(KERN_INFO "Too many packets in the buffer queue, try to reinject.\n");
        reinject_pkts = 1;
    }
    
    //reinject packets
    //here we make sure packets has been queue for enough time before put in back on line.
    if (reinject_pkts) {
        list_for_each_entry_safe(q, qnext, &head_entry.list, list) {

            //find corresponding traffic data for this queued packet.
            for (tp=qlp; tp!=&headt; tp=dclist_outer(tp->list.prev, tfc_t, list)){
                if (tp->id == get_pkt_id(iph) && time_shift_passed(tp->time, time_shift)){
                    list_del(&q->list);
                    printk(KERN_INFO "::::::Reinject: %d\n", q->id);
                    nf_reinject(q, NF_ACCEPT);
                    pkt_num_in_q--;
                    break;
                }
            }
        }
        reinject_pkts = 0;
    }

    if (pkt_num_in_q >= 50) {
        list_for_each_entry_safe(q, qnext, &head_entry.list, list) {
            list_del(&q->list);
            printk(KERN_INFO "::::::Reinject (queue too long): %d\n", q->id);
            nf_reinject(q, NF_ACCEPT);
            pkt_num_in_q--;
            if (pkt_num_in_q <= 40)
                break;
        }
    }
    return 1;
}


static struct nf_queue_handler queuehandler = {
    .name = "TrafficSchedulerQueue",
    .outfn = &queue_callback
};

/**
 * KERNEL MODULE related
 ============================================================================*/

/**
 * module init
 */
static int __init pkts_init(void) {
    int ret;

    if((target_ip = k_v4pton(target)) == 0)
        return -1;

    printk(KERN_INFO "%s > 0x%08X\n", target, target_ip);

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

/**
 * module exit
 */
static void __exit pkts_exit(void) {
    tfc_t *tp;
    struct lnode *ln, *ltemp;
    nf_unregister_queue_handlers(&queuehandler);
    nf_unregister_hook(&pkt_ops);
    
    remove_proc_entry(PROC_F_PREDICTION, proc_dir);
    remove_proc_entry(PROC_DIR, NULL);

    // free memory 
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

