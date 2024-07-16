mount -t bpf bpf /sys/fs/bpf/           #-t 表示挂在的文件系统类型为bpf，第二个bpf是挂载点的名称，表示bpf文件系统将被挂载到/sys/fs/bpf/这个目录下


clang-10 -O2 -g -target bpf -c bpf_sockops_v4.c -o bpf_sockops_v4.o  #用clang编译器编译一个ebpf程序，-02 使用第二级优化，-g 生成调试信息， -target bpf 编译目标为bpf，告诉clang编译器输出适合在linux内核bpf虚拟机上运行的代码，-c 仅编译不链接，这将生成目标文件而不是可执行文件
bpftool prog load bpf_sockops_v4.o "/sys/fs/bpf/bpf_sockops"         #
bpftool cgroup attach "/sys/fs/cgroup/unified/" sock_ops pinned "/sys/fs/bpf/bpf_sockops"


bpftool map pin id `bpftool prog show pinned "/sys/fs/bpf/bpf_sockops" | grep -o -E 'map_ids [0-9,]+' | awk 'BEGIN{FS=","} {print$2}'` "/sys/fs/bpf/sock_ops_map"

bpftool map pin id `bpftool prog show pinned "/sys/fs/bpf/bpf_sockops" | grep -o -E 'map_ids [0-9]+' | awk 'BEGIN{FS=" "} {print$2}'` "/sys/fs/bpf/svc_ip_map"

clang-10 -O2 -g -Wall -target bpf -c bpf_tcpip_bypass.c -o bpf_tcpip_bypass.o
bpftool prog load bpf_tcpip_bypass.o "/sys/fs/bpf/bpf_tcpip_bypass" map name sock_ops_map pinned "/sys/fs/bpf/sock_ops_map" map name svc_ip pinned "/sys/fs/bpf/svc_ip_map"
bpftool prog attach pinned "/sys/fs/bpf/bpf_tcpip_bypass" msg_verdict pinned "/sys/fs/bpf/sock_ops_map"
