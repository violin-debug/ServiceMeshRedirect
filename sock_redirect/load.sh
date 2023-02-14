mount -t bpf bpf /sys/fs/bpf/

clang-10 -O2 -g -target bpf -c bpf_sockops_v4.c -o bpf_sockops_v4.o
bpftool prog load bpf_sockops_v4.o "/sys/fs/bpf/bpf_sockops"
bpftool cgroup attach "/sys/fs/cgroup/unified/" sock_ops pinned "/sys/fs/bpf/bpf_sockops"


bpftool map pin id `bpftool prog show pinned "/sys/fs/bpf/bpf_sockops" | grep -o -E 'map_ids [0-9,]+' | awk 'BEGIN{FS=","} {print$2}'` "/sys/fs/bpf/sock_ops_map"

bpftool map pin id `bpftool prog show pinned "/sys/fs/bpf/bpf_sockops" | grep -o -E 'map_ids [0-9]+' | awk 'BEGIN{FS=" "} {print$2}'` "/sys/fs/bpf/svc_ip_map"

clang-10 -O2 -g -Wall -target bpf -c bpf_tcpip_bypass.c -o bpf_tcpip_bypass.o
bpftool prog load bpf_tcpip_bypass.o "/sys/fs/bpf/bpf_tcpip_bypass" map name sock_ops_map pinned "/sys/fs/bpf/sock_ops_map" map name svc_ip pinned "/sys/fs/bpf/svc_ip_map"
bpftool prog attach pinned "/sys/fs/bpf/bpf_tcpip_bypass" msg_verdict pinned "/sys/fs/bpf/sock_ops_map"
