#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_sockops.h"

//sock_ops是BPF的一个程序类型，可以操作套接字，可以附加到套接字上


//静态：函数只能在定义它的编译单元内部访问。
//内联：编译器可以考虑在每个调用点展开函数体，以减少调用开销。
static inline 
void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
	// trace
	if(skops->local_port == 15021 || bpf_ntohl(skops->remote_port) == 15021){ //15021端口是与Istio中的入口网关相关ingress gateway
		return ;
	}
	// bpf_printk("<<< ipv4 op = %d, port %d --> %d from skops",skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
	// bpf_printk("<<< ipv4 op = %d, addr %x --> %x from skops", skops->op, skops->local_ip4, skops->remote_ip4);

	//提取套接字本地及远程ip+端口号
	__u32 local_ip = skops->local_ip4;
	__u32 local_port = skops->local_port;
	__u32 remote_ip = skops->remote_ip4;
	__u32 remote_port = skops->remote_port;

	int is_update = 0; //是否需要更细套接字信息
	
	struct ip_port remoteSvc = {};
	remoteSvc.ip4 = remote_ip; 
	remoteSvc.port = remote_port;
	int *if_in_svc_ip = bpf_map_lookup_elem(&svc_ip, &remoteSvc); //检查远程IP是否为目标服务IP
	if(if_in_svc_ip != NULL){ // target Address //远程ip==目标服务ip，更新
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

	if (is_update == 1){ //构建sock_key结构体并用更新套接字sock_ops_map
		// bpf_printk("<<< ipv4 op = %d, port %d --> %d from skops",skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
        	// bpf_printk("<<< ipv4 op = %d, addr %x --> %x from skops", skops->op, skops->local_ip4, skops->remote_ip4);

		struct sock_key key = {};
		key.dip4 = remote_ip;
		key.dport = remote_port;
		key.sip4 = local_ip;
		key.sport = bpf_htonl(local_port); //将一个网络字节序表示的32位无符号整数转换成主机字节序，主机字节序可能是大端序，也可能是小端序，这个操作是保证了网络字节序与主机字节序相同
		int ret = bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_ANY);
		if (ret != 0) {
			bpf_printk("FAILED: sock_hash_update ret: %d", ret);
		}else{
			// bpf_printk("Success! updated sock_hash");
		}
	}
}

SEC("sockops") //SEC宏，告诉BPF编译器这段代码该被加载到哪个section中，这是eBPF加载器识别和加载程序的重要部分。
int bpf_sockops_v4(struct bpf_sock_ops *skops) //定义了一个处理ipv4套接字的函数，参数skops是一个指向bpf_sock_ops结构的指针，该结构包含了有关当前套接字操作的信息
{
	__u32 family, op;

	family = skops->family; //从skops中提取出family字段，family表示套接字的地址族，如ipv4/ipv6
	op = skops->op; //要执行的操作类型

	switch (op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: //当被动套接字（服务端）上的TCP连接被建立时触发
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:  //当主动套接字（客户端）上的TCP连接被建立时出发
		// case BPF_SOCK_OPS_TIMEOUT_INIT:	// used when 15006
			if (family == 2) { //AF_INET //检查套接字是否属于ipv4协议族（AF_INET）,如果是，调用bpf_sock_ops_ipv4函数进一步处理
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
