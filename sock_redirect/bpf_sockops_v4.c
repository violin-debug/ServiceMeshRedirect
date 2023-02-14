#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_sockops.h"



static inline
void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
	// trace
	if(skops->local_port == 15021 || bpf_ntohl(skops->remote_port) == 15021){
		return ;
	}
	// bpf_printk("<<< ipv4 op = %d, port %d --> %d from skops",skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
	// bpf_printk("<<< ipv4 op = %d, addr %x --> %x from skops", skops->op, skops->local_ip4, skops->remote_ip4);

	__u32 local_ip = skops->local_ip4;
	__u32 local_port = skops->local_port;
	__u32 remote_ip = skops->remote_ip4;
	__u32 remote_port = skops->remote_port;

	int is_update = 0;
	
	struct ip_port remoteSvc = {};
	remoteSvc.ip4 = remote_ip;
	remoteSvc.port = remote_port;
	int *if_in_svc_ip = bpf_map_lookup_elem(&svc_ip, &remoteSvc);
	if(if_in_svc_ip != NULL){ // target Address
		is_update = 1;
	}

	if (!is_update && local_ip ==  0x0100007F && local_port == 15001) {	// 127.0.0.1:15001
		is_update = 1;
	}

	if (!is_update && (local_ip == 0x0600007F  || remote_ip == 0x0600007F)) {	// 127.0.0.6
		is_update = 1;
	}
	if (!is_update && local_port == 15006){
		is_update = 1;
	}

	if (is_update == 1){
		// bpf_printk("<<< ipv4 op = %d, port %d --> %d from skops",skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
        	// bpf_printk("<<< ipv4 op = %d, addr %x --> %x from skops", skops->op, skops->local_ip4, skops->remote_ip4);

		struct sock_key key = {};
		key.dip4 = remote_ip;
		key.dport = remote_port;
		key.sip4 = local_ip;
		key.sport = bpf_htonl(local_port);
		int ret = bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_ANY);
		if (ret != 0) {
			bpf_printk("FAILED: sock_hash_update ret: %d", ret);
		}else{
			// bpf_printk("Success! updated sock_hash");
		}
	}
}

SEC("sockops")
int bpf_sockops_v4(struct bpf_sock_ops *skops)
{
	__u32 family, op;

	family = skops->family;
	op = skops->op;

	switch (op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		// case BPF_SOCK_OPS_TIMEOUT_INIT:	// used when 15006
			if (family == 2) { //AF_INET
				bpf_sock_ops_ipv4(skops);
			}
			break;
		default:
			break;
	}
	return 0;
}

char ____license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
