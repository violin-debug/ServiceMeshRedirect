clang-10 -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -c kprobe_sock_recvmsg.bpf.c -o kprobe_sock_recvmsg.bpf.o
bpftool gen skeleton kprobe_sock_recvmsg.bpf.o > kprobe_sock_recvmsg.skel.h
clang kprobe_sock_recvmsg.c -lbpf -lelf -o kprobe_sock_recvmsg
./kprobe_sock_recvmsg
echo "SUCCESS !\n"
