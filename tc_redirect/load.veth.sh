VETH_1="veth0"
cmd=$0

if [ $# -ne 1 ]
then
        echo "ERROR: The imput is illegal!\n"
        echo "----- usage: ${cmd} IFNAME\n"
        echo "This script is to load tc-redirect bpf program in ingress and tc-pass on egress of ifindex IFNAME"
else
        VETH_1=$1
        # compile
        clang -O2 -target bpf -c my_tc_l2_redirect_kern_veth.c -o my_tc_l2_redirect_kern_veth.o
	tc qdisc add dev ${VETH_1} clsact

	# redirect
	tc filter add dev ${VETH_1} ingress bpf da obj my_tc_l2_redirect_kern_veth.o sec tc_ingress_redirect
	# tc filter add dev ${VETH_1} egress bpf da obj my_tc_l2_redirect_kern.o sec tc_pass
	# tc filter add dev ${VETH_1} egress bpf da obj my_tc_l2_redirect_kern.o sec tc_info
fi
