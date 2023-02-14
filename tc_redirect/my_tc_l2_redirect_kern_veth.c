#define KBUILD_MODNAME "foo"

// #include "../include/vmlinux.h"
#include "../include/if_ether.h"
#include "../include/pkt_cls.h"


#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
// #include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
// #include <uapi/linux/ip.h>
// #include <uapi/linux/in.h>
// #include <uapi/linux/tcp.h>
// #include <uapi/linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct iphdr {
	__u8	ihl:4,
		version:4;
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	/*The options start here. */
};

struct bpf_map_def {
        __u32 type;
        __u32 key_size;
        __u32 value_size;
        __u32 max_entries;
        __u32 map_flags;
};

#define PIN_GLOBAL_NS		2
struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
};

/* copy of 'struct ethhdr' without __packed */
struct eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	unsigned short  h_proto;
};

struct addr_pair{
	__u32 src_pod_ip;
	__u32 dst_pod_ip;
};

// record ifindex information
struct ifindex_info{
	int ifindex;				// redirected ifindex
	unsigned char changed_src_mac[ETH_ALEN];	// if is sent outside, change the source mac address
	unsigned char changed_dest_mac[ETH_ALEN];	// if is snet outside, change the destination mac address
};
/*
struct bpf_map_def SEC("maps") podip_to_ifindex = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct addr_pair),
        .value_size = sizeof(struct ifindex_info),
        .max_entries = 20,
};
*/

struct bpf_elf_map SEC("maps") podip_to_ifindex = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(struct addr_pair),
	.size_value = sizeof(struct ifindex_info),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 200,
};


SEC("tc_info")
int tc_info_prog(struct __sk_buff *skb)
{
        void *data = (void *)(long)skb->data;
	struct eth_hdr *eth = data;
	void *data_end = (void *)(long)skb->data_end;		   
   	int ret = TC_ACT_OK;
	__u32 len = skb->len;
	if (data + sizeof(*eth) > data_end)
		return TC_ACT_OK;
	
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + sizeof(*eth);
		if (data + sizeof(*eth) + sizeof(*iph) > data_end)
			return TC_ACT_OK;
		
		__be32 daddr = iph->daddr;
		__be32 saddr = iph->saddr;
		
		if(daddr == 0xa95174ca ){
			return TC_ACT_OK;
		}
		__u32 sk_ingress_ifindex = skb->ingress_ifindex, sk_ifindex = skb->ifindex, sk_tc_index = skb->tc_index;

		char iffmt[] = "Ingress_ifindex: %d, ifindex: %d, tc_index: %d";
		bpf_trace_printk(iffmt, sizeof(iffmt), sk_ingress_ifindex, sk_ifindex, sk_tc_index);
		char fmt[] = "From saddr[%x] to daddr[%x], length: %d";
		bpf_trace_printk(fmt, sizeof(fmt), saddr, daddr, len );
		char mac1[] = "Source mac1: %x:%x:%x";
		bpf_trace_printk(mac1, sizeof(mac1), eth->h_source[0], eth->h_source[1], eth->h_source[2]);
		char mac2[] = "Source mac2: %x:%x:%x";
		bpf_trace_printk(mac2, sizeof(mac2), eth->h_source[3], eth->h_source[4], eth->h_source[5]);
		char mac3[] = "Dest mac1: %x:%x:%x";
		bpf_trace_printk(mac3, sizeof(mac3), eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
        	char mac4[] = "Dest mac2: %x:%x:%x";		
		bpf_trace_printk(mac4, sizeof(mac4), eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);				        
	
	}
	return TC_ACT_OK;
}


SEC("tc_ingress_redirect")
int tc_ingress_redirect_prog(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	struct eth_hdr *eth = data;
	void *data_end = (void *)(long)skb->data_end;
	struct bpf_tunnel_key tkey = {};

	// if unhealthy packet
	if (data + sizeof(*eth) > data_end)
		return TC_ACT_OK;	

	// ipv4 packet
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {

		struct iphdr *iph = data + sizeof(*eth);
		
		if (data + sizeof(*eth) + sizeof(*iph) > data_end)
			return TC_ACT_OK;
	
		struct addr_pair packet_addrs = {};

		packet_addrs.dst_pod_ip = iph->daddr;
		packet_addrs.src_pod_ip = iph->saddr;
		
		// print source address and destination address of the packet
		//char fmt[] = "Ingress: from saddr[%x] to daddr[%x], length: %d";
		//bpf_trace_printk(fmt, sizeof(fmt), saddr, daddr, len);
		 
		// find redirect ifindex
		
		struct ifindex_info *ifindex_info = bpf_map_lookup_elem(&podip_to_ifindex, &packet_addrs);
		if(!ifindex_info)
			return TC_ACT_OK;

		int ifindex = ifindex_info->ifindex;
		
		// char fmt[] = "Received: from saddr[%x] to daddr[%x]";
		// bpf_trace_printk(fmt, sizeof(fmt), packet_addrs.src_pod_ip, packet_addrs.dst_pod_ip);

		// char infofmt[] = "Find ifindex:%d, isChangeMac:%d";
		// bpf_trace_printk(infofmt, sizeof(infofmt), ifindex, isChangeMac);		
		
		//char changefmt[] = "Changing mac address...";
		//bpf_trace_printk(changefmt, sizeof(changefmt));
		__builtin_memcpy(data, ifindex_info->changed_dest_mac, ETH_ALEN);
		__builtin_memcpy(data + ETH_ALEN, ifindex_info->changed_src_mac, ETH_ALEN);
		
		// char mac1[] = "Source mac1: %x:%x:%x";
		// bpf_trace_printk(mac1, sizeof(mac1), eth->h_source[0], eth->h_source[1], eth->h_source[2]);
		// char mac2[] = "Dest mac1: %x:%x:%x";
		// bpf_trace_printk(mac2, sizeof(mac2), eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
		


		// redirect 1: redirect but not print the result
		return bpf_redirect(ifindex, 0);
		
		// redirect 2: redirect packet and print the result of redirection
		// int ret = bpf_redirect(ifindex, 0);
		// char fmt4[] = "Redirect daddr:%d to ifindex:%d, redirect result: %d";	
		// bpf_trace_printk(fmt4, sizeof(fmt4), packet_addrs.dst_pod_ip, ifindex, ret);
		// return ret;
		
	}

	return TC_ACT_OK;

}
						
SEC("tc_pass")
int tc_pass_prog(struct __sk_buff *skb){
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
char _version[] SEC("version") = "1";
