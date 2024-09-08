#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>
#include<linux/if_ether.h>
#include<bpf/bpf_endian.h>

//map to keep the counter 
struct { 
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
}counter_map SEC("maps");

//perf event struct to read the messages/logs from
struct { 
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12); //2 pow 24 entries
}log_map SEC("maps");

struct log_entry{ 
    __u64 timestamp;
    __u32 proto_no;
};

enum ip_prot{ 
    IPV4 = 1, 
    IPV6 = 2, 
    ARP = 3,
    OTHER = 4,
};

long lookup_protocol(struct xdp_md *ctx){ 

    void *data_start = (void*)(long) ctx->data;
    void *data_end = (void *)(long) ctx->data_end; 
    if (data_start + sizeof(struct ethhdr) > data_end){
        return 0;
    }
    struct ethhdr *eth = data_start;
    
    enum ip_prot ret;
    int protocol = bpf_ntohs(eth->h_proto);
    switch (protocol)
    {
    case ETH_P_IP:
        ret = IPV4;
        break;
    case ETH_P_ARP:
        ret = ARP;
        break;
    case ETH_P_IPV6:
        ret = IPV6;
        break;
    default:
        ret = OTHER;
        break;
    }
    return ret;
}

void logger(struct log_entry *log, long pn){ 
        log->timestamp = bpf_ktime_get_ns();
        log->proto_no = pn;
        bpf_ringbuf_output(&log_map, (void *)log, sizeof(log), 0);
        return;
}
/* 
XDP program 
Checks the type of protocol on the packets
Logs it in the map by increasing the counter for that packet
*/
SEC("xdp")
int xdp_packet_protocol_counter(struct xdp_md *ctx){ 

    // get the protocol which is run
    long protocol = lookup_protocol(ctx);
    struct log_entry log = {};
    logger(&log, protocol);
    if (protocol < 1){ 
        //malacious packet error
        // print something
        return XDP_PASS;

    }
    // based on the protocol update on the map
    enum ip_prot key = protocol;
    //check if key exists with a value
    //if not update with 1
    __u64 *value = bpf_map_lookup_elem(&counter_map, &key); 
    if (!value){
        (*value) = 1;  
        bpf_map_update_elem(&counter_map, &key, value, BPF_NOEXIST);
    }else {
        //if it does update by one
       (*value) ++;
        bpf_map_update_elem(&counter_map, &key, value, BPF_EXIST);
    }
    return XDP_PASS;
    
}