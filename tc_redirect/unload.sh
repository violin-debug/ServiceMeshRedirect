VETH_1="veth0"
cmd=$0

if [ $# -ne 1 ]
then
	echo "ERROR: The input is illegal!";
	echo "---- usage: ${cmd} IFNAME\n"
	echo "Warnning: This shell script is trying to remove the tc bpf programs loaded in IFNAME both in ingress and egress."

else
	VETH_1=$1
	# remove tc bpf program in VETH_1 and VETH_2 both in ingress and egress
	tc filter delete dev ${VETH_1} ingress
	tc filter delete dev ${VETH_1} egress
	echo "Successfully remove tc bpf programs loaded on ${VETH_1} and ${VETH_2} both in ingress and egress"
fi

