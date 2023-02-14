#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
// #include "../include/bpf/libbpf.h"
// #include "../include/kprobe_type.h"
#include "kprobe_sock_recvmsg.skel.h"

struct rb_event {
	__u16 type;
        __u32 src_ip;
        __u32 dst_ip;
        __u16 src_port;
        __u16 dst_port;
        __u64 timestamp;
} __attribute__((packed));

/* IP Address (ip:port) */
struct ip_port{
    __u32 ip4;
    __u16 port;
} __attribute__((packed));


int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}


static void bump_memlock_rlimit(void)
{
        struct rlimit rlim_new = {
                .rlim_cur       = RLIM_INFINITY,
                .rlim_max       = RLIM_INFINITY,
        };

        if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
                fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
                exit(1);
        }
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}


int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct rb_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	
	char type[5] = "recv";
	if (e->type == 0){
		type[0] = 's';
		type[1] = 'e';
		type[2] = 'n';
		type[3] = 'd';
	}

	FILE * fp = fopen("result.txt", "a+");
	fprintf(fp, "%s, %s, %x, %d, %x, %d, %llu\n", ts, type, e->src_ip, e->src_port, e->dst_ip, e->dst_port, e->timestamp);
	fclose(fp);

	return 0;
}


int main(void)
{
	libbpf_set_print(libbpf_print_fn);
	bump_memlock_rlimit();

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	struct kprobe_sock_recvmsg_bpf *skel = kprobe_sock_recvmsg_bpf__open();
    	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	int err = kprobe_sock_recvmsg_bpf__load(skel);
	if (err) {
                fprintf(stderr, "Failed to load BPF skeleton\n");
                goto cleanup;
        }
	
	err = kprobe_sock_recvmsg_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Update: "svc_ip" */
	struct ip_port test_key = {
		.ip4 = 0x7F000001,
		.port = 15001,
	}; // 127.0.0.1:15001
	int test_value = 1;
	int map_fd = bpf_map__fd(skel->maps.svc_ip);
	int update_ret = bpf_map_update_elem(bpf_map__fd(skel->maps.svc_ip), &test_key, &test_value, BPF_ANY);
	printf("Updated, map_fd = %d, ret = %d\n", map_fd, update_ret);
	
	// service_ip:port
	test_key.ip4 = 0xA6F4D52;
	test_key.port = 9080;
	update_ret = bpf_map_update_elem(bpf_map__fd(skel->maps.svc_ip), &test_key, &test_value, BPF_ANY);
        printf("Updated, map_fd = %d, ret = %d\n", map_fd, update_ret);
	test_key.ip4 = 0xA647E02;
	update_ret = bpf_map_update_elem(bpf_map__fd(skel->maps.svc_ip), &test_key, &test_value, BPF_ANY);
        printf("Updated, map_fd = %d, ret = %d\n", map_fd, update_ret);
	test_key.ip4 = 0xA690D7B;
        update_ret = bpf_map_update_elem(bpf_map__fd(skel->maps.svc_ip), &test_key, &test_value, BPF_ANY);
        printf("Updated, map_fd = %d, ret = %d\n", map_fd, update_ret);

	// server_ip:port
	test_key.ip4 = 0xAF40276;
        update_ret = bpf_map_update_elem(bpf_map__fd(skel->maps.svc_ip), &test_key, &test_value, BPF_ANY);
        printf("Updated, map_fd = %d, ret = %d\n", map_fd, update_ret);
	test_key.ip4 = 0xAF40274;
        update_ret = bpf_map_update_elem(bpf_map__fd(skel->maps.svc_ip), &test_key, &test_value, BPF_ANY);
        printf("Updated, map_fd = %d, ret = %d\n", map_fd, update_ret);
	test_key.ip4 = 0xAF40275;
        update_ret = bpf_map_update_elem(bpf_map__fd(skel->maps.svc_ip), &test_key, &test_value, BPF_ANY);
        printf("Updated, map_fd = %d, ret = %d\n", map_fd, update_ret);


	/* Set up ring buffer polling */
	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.trace_ringbuf), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	FILE * fp = fopen("result.txt", "a+");

	/* Process events */
	fprintf(fp, "%s, %s, %s, %s, %s, %s, %s\n",
	       "TIME", "TYPE", "SIP", "DPORT", "DIP", "DPORT", "TIMESTAMP");
	fclose(fp);
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	kprobe_sock_recvmsg_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
 
