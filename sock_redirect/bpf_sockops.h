/*
 * Map definition
 * Why should we reuse the map definition bpf_elf_map
 * from iproute2/bpf_elf.h?
 */
struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

struct sock_key {
	__u32 sip4;
	__u32 dip4;
//	uint8_t  family;
//	uint8_t  pad1;
//	uint16_t pad2;
	// this padding required for 64bit alignment
	// else ebpf kernel verifier rejects loading
	// of the program
//	uint32_t pad3;
	__u32 sport;
	__u32 dport;
} __attribute__((packed));


struct bpf_map_def SEC("maps") sock_ops_map = {
	.type           = BPF_MAP_TYPE_SOCKHASH,
	.key_size       = sizeof(struct sock_key),
	.value_size     = sizeof(int),
	.max_entries    = 65535,
	.map_flags      = 0,
};


struct ip_port{
    __u32 ip4;
    __u32 port;
};

struct bpf_map_def SEC("maps") svc_ip = {
	.type		= BPF_MAP_TYPE_HASH,
	.key_size	= sizeof(struct ip_port), // svc/pod ip:port
	.value_size 	= sizeof(int),	// 1: redirection in a pod, 2: redirection between pods
	.max_entries 	= 100,
};