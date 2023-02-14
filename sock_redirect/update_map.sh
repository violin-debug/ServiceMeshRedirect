# bookinfo
## productpage -> detail, reviews
bpftool map update pinned "/sys/fs/bpf/svc_ip_map" key 10 103 149 224 0 0 0x23 0x78 value 1 0 0 0 any
bpftool map update pinned "/sys/fs/bpf/svc_ip_map" key 10 100 178 170 0 0 0x23 0x78 value 1 0 0 0 any
### detail pod ip
bpftool map update pinned "/sys/fs/bpf/svc_ip_map" key 10 244 2 238 0 0 0x23 0x78 value 2 0 0 0 any
bpftool map update pinned "/sys/fs/bpf/svc_ip_map" key 10 244 2 249 0 0 0x23 0x78 value 2 0 0 0 any
bpftool map update pinned "/sys/fs/bpf/svc_ip_map" key 10 244 2 241 0 0 0x23 0x78 value 2 0 0 0 any
# bpftool map delete pinned "/sys/fs/bpf/svc_ip_map" key 10 244 2 185 0 0 0x23 0x78 
# bpftool map delete pinned "/sys/fs/bpf/svc_ip_map" key 10 244 2 191 0 0 0x23 0x78 
# bpftool map delete pinned "/sys/fs/bpf/svc_ip_map" key 10 244 2 184 0 0 0x23 0x78 

# hipster
## checkout -> shipping, payment, email
# bpftool map update pinned "/sys/fs/bpf/svc_ip_map" key 10 110 51 19 0 0 0xc3 0x83 value 1 0 0 0 any
# bpftool map update pinned "/sys/fs/bpf/svc_ip_map" key 10 111 64 64 0 0 0xc3 0x83 value 1 0 0 0 any
# bpftool map update pinned "/sys/fs/bpf/svc_ip_map" key 10 106 234 172 0 0 0x13 0x88 value 1 0 0 0 any
## recommedation -> productcatalog
bpftool map update pinned "/sys/fs/bpf/svc_ip_map" key 10 99 9 3 0 0 0x0d 0xde value 1 0 0 0 any
# bpftool map delete pinned "/sys/fs/bpf/svc_ip_map" key 10 109 188 194 0 0 0x0d 0xde
