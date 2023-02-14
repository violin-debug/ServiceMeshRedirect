#include "../include/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// definitions 

// part of <bpf/bpf_tracing.h>
#include "../include/bpf_tracing.h"

struct bpf_map_def {
        __u32 type;
        __u32 key_size;
        __u32 value_size;
        __u32 max_entries;
        __u32 map_flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024*1024);
} trace_ringbuf SEC(".maps");

struct rb_event {
        __u16 type;
	__u32 src_ip;
        __u32 dst_ip;
        __u16 src_port;
        __u16 dst_port;
        __u64 timestamp;
} __attribute__((packed));

/* IP address (ip:port) */
struct ip_port{
    __u32 ip4;
    __u16 port;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, struct ip_port);
    __type(value, int);
} svc_ip SEC(".maps");


SEC("kprobe/sock_recvmsg")
int BPF_KPROBE(sock_recvmsg, struct socket *sok, struct msghdr *msg, int flags)
{
    struct sock * sk = BPF_CORE_READ(sok, sk);
    struct sock_common skp = BPF_CORE_READ(sk, __sk_common);

    // target Address（ip:port）
    // change to host order
    struct ip_port src_addr_pair = {
	.ip4 = bpf_ntohl(skp.skc_rcv_saddr),
        .port = skp.skc_num,
    }; // source 

    struct ip_port dst_addr_pair = {
        .ip4 = bpf_ntohl(skp.skc_daddr),
        .port = bpf_ntohs(skp.skc_dport),
    }; // destination
    
    struct rb_event event_data = {
                .type = 1,
	    	    .src_ip = bpf_ntohl(skp.skc_rcv_saddr),
                .dst_ip = bpf_ntohl(skp.skc_daddr),
                .src_port = skp.skc_num,
                .dst_port = bpf_ntohs(skp.skc_dport),
                .timestamp = bpf_ktime_get_boot_ns(),
        };

    int *is_target = bpf_map_lookup_elem(&svc_ip, &src_addr_pair);
    if(is_target != NULL){
	    bpf_ringbuf_output(&trace_ringbuf, &event_data, sizeof(event_data), 0);
	}
	
    is_target = bpf_map_lookup_elem(&svc_ip, &dst_addr_pair);
    if(is_target != NULL){
    	bpf_ringbuf_output(&trace_ringbuf, &event_data, sizeof(struct rb_event), 0);
    }	

    return 0;
}

SEC("kprobe/sock_sendmsg")
int BPF_KPROBE(sock_sendmsg, struct socket *sok, struct msghdr *msg)
{
    struct sock * sk = BPF_CORE_READ(sok, sk);
    struct sock_common skp = BPF_CORE_READ(sk, __sk_common);

    // target Address（ip:port）
    // change to host order
    struct ip_port src_addr_pair = {
	.ip4 = bpf_ntohl(skp.skc_rcv_saddr),
        .port = skp.skc_num,
    }; // source

    struct ip_port dst_addr_pair = {
        .ip4 = bpf_ntohl(skp.skc_daddr),
        .port = bpf_ntohs(skp.skc_dport),
    }; // destination

    struct rb_event event_data = {
            .type = 0,
		    .src_ip = bpf_ntohl(skp.skc_rcv_saddr),
            .dst_ip = bpf_ntohl(skp.skc_daddr),
            .src_port = skp.skc_num,
            .dst_port = bpf_ntohs(skp.skc_dport),
            .timestamp = bpf_ktime_get_boot_ns(),
        };

    int *is_target = bpf_map_lookup_elem(&svc_ip, &src_addr_pair);
    if(is_target != NULL){
        bpf_ringbuf_output(&trace_ringbuf, &event_data, sizeof(struct rb_event), 0);
    }

    is_target = bpf_map_lookup_elem(&svc_ip, &dst_addr_pair);
    if(is_target != NULL){
        bpf_ringbuf_output(&trace_ringbuf, &event_data, sizeof(struct rb_event), 0);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;
