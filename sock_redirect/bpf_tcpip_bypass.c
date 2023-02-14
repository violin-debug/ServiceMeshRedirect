#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_sockops.h"



struct bpf_map_def SEC("maps") pod_to_svc_map = {
        .type           = BPF_MAP_TYPE_HASH,
        .key_size       = sizeof(struct ip_port),
        .value_size     = sizeof(struct ip_port),
        .max_entries    = 50000,
};

/* extract the key that identifies the destination socket in the sock_ops_map */
static inline
void sk_msg_extract_key(struct sk_msg_md *msg,
	struct sock_key *key)
{
	__u32 remote_ip = msg->remote_ip4;
	__u32 remote_port = msg->remote_port;
	__u32 local_ip = msg->local_ip4;
	__u32 local_port = msg->local_port;

	// 1. if 127.0.0.6
	if (local_ip == 0x600007F || remote_ip == 0x600007F){
		// exchange
        	key->sip4 = remote_ip;                  // stored in network byte order
               	key->dip4 = local_ip;                   // stored in network byte order
                key->dport = bpf_htonl(local_port); // local_port stored in host byte order
                key->sport = remote_port; // remote_port stored in network byte order
	}


	// target Address
	struct ip_port remoteSvc = {};
	remoteSvc.ip4 = remote_ip;
	remoteSvc.port = remote_port;
	int *if_in_svc_ip = bpf_map_lookup_elem(&svc_ip, &remoteSvc);
	// extract key

	// 2. send to svc/pod ip:port
	if(if_in_svc_ip != NULL){
		int redirection_direct = *if_in_svc_ip;
		if( redirection_direct == 1){// redirection in a pod : replace the svc ip:port with 127.0.0.1:15001
			// keep ip and port in network byte order
			struct ip_port clientKey = { local_ip, bpf_htonl(local_port)};
			struct ip_port clientValue = { remote_ip, remote_port};

			// updata pod_to_svc_map
			bpf_map_update_elem(&pod_to_svc_map, &clientKey, &clientValue, BPF_ANY);

			key->sip4 = 0x100007F;	// 127.0.0.1
			__u32 tmp_port = 15001;
			key->sport = bpf_htonl(tmp_port);
			key->dip4 = local_ip;
			key->dport = bpf_htonl(local_port);
			//	key->family = 1;
		}else if( redirection_direct == 2){ // redirection between pods : replace the port with 15006
			// keep ip and port in network byte order
			struct ip_port clientKey = { local_ip, bpf_htonl(local_port)};
			struct ip_port clientValue = { remote_ip, remote_port};

			// update pod_to_svc_map
			bpf_map_update_elem(&pod_to_svc_map, &clientKey, &clientValue, BPF_ANY);
			key->sip4 = remote_ip;
			__u32 tmp_port = 15006;	// only modify dest_port
			key->sport = bpf_htonl(tmp_port);
			key->dip4 = local_ip;
			key->dport = bpf_htonl(local_port);
		}
	}

	else if(local_ip ==  0x0100007F && local_port == 15001){ // 127.0.0.15001
			struct ip_port clientValue = { remote_ip, remote_port};
			key->dip4 = local_ip;
			key->dport = bpf_htonl(local_port);
			struct ip_port* dvalue = bpf_map_lookup_elem(&pod_to_svc_map, &clientValue);
			// delete elem in pod_to_svc_map
			if (dvalue != NULL){
				key->dip4 = dvalue->ip4;
				key->dport = dvalue->port;
				// delete elem in pod_to_svc_map when found
				bpf_map_delete_elem(&pod_to_svc_map, &clientValue);
			}
			key->sip4 = remote_ip;
			key->sport = remote_port;
	}
	// 15006
	else if( local_port == 15006){
		struct ip_port clientValue = { remote_ip, remote_port};
		key->dip4 = local_ip;
		key->dport = bpf_htonl(local_port);
		struct ip_port* dvalue = bpf_map_lookup_elem(&pod_to_svc_map, &clientValue);
		// delete elem in pod_to_svc_map
		if (dvalue != NULL){
			key->dip4 = dvalue->ip4;
			key->dport = dvalue->port;
			// delete elem in pod_to_svc_map when found
			bpf_map_delete_elem(&pod_to_svc_map, &clientValue);
		}
		key->sip4 = remote_ip;
		key->sport = remote_port;
	}
}

SEC("sk_msg")
int bpf_tcpip_bypass(struct sk_msg_md *msg)
{
    struct  sock_key key = {};
    sk_msg_extract_key(msg, &key);

    // int ret =
	    bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
    // bpf_printk("<<<<<< msg redirect>>>>>> From SAddr[%x] to DAddr[%x]: ret %d", msg->local_ip4, msg->remote_ip4, ret);

    return SK_PASS;
}

char ____license[] SEC("license") = "GPL";
