# # bookinfo

# # for productpage-veth
# # (eth0, ?)
# bpftool map update id 307 key 10 14 0 42 10 14 0 212 value 2 0 0 0 0x0 0x16 0x3e 0x18 0xe6 0x06 0xee 0xff 0xff 0xff 0xff 0xff
# bpftool map update id 307 key 10 14 0 42 10 14 1 13 value 2 0 0 0 0x0 0x16 0x3e 0x18 0xe6 0x06 0xee 0xff 0xff 0xff 0xff 0xff

# # for eth0
# # (cni0, pod mac)
# bpftool map update id 301 key 10 14 0 212 10 14 0 42 value 45 0 0 0 0x62 0x77 0xd6 0x56 0x1d 0xb6 0x3e 0x11 0x4e 0xd1 0xdd 0xd3
# bpftool map update id 301 key 10 14 1 13 10 14 0 42 value 45 0 0 0 0x62 0x77 0xd6 0x56 0x1d 0xb6 0x3e 0x11 0x4e 0xd1 0xdd 0xd3
# bpftool map update id 301 key 10 14 1 13 10 14 0 37 value 40 0 0 0 0x62 0x77 0xd6 0x56 0x1d 0xb6 0x66 0x59 0xaf 0x2f 0x15 0xa0
# bpftool map update id 301 key 10 14 0 212 10 14 0 37 value 40 0 0 0 0x62 0x77 0xd6 0x56 0x1d 0xb6 0x66 0x59 0xaf 0x2f 0x15 0xa0

# # for rating
# bpftool map update id 313 key 10 14 0 37 10 14 1 13 value 2 0 0 0 0x0 0x16 0x3e 0x18 0xe6 0x06 0xee 0xff 0xff 0xff 0xff 0xff
# bpftool map update id 313 key 10 14 0 37 10 14 0 212 value 2 0 0 0 0x0 0x16 0x3e 0x18 0xe6 0x06 0xee 0xff 0xff 0xff 0xff 0xff


from threading import local
import yaml

# read yaml
def readYaml(yamlPath):
    f = open(yamlPath, 'r', encoding='utf-8')
    cfg = f.read()
    d = yaml.load(cfg)  # change to dist
    f.close()
    return d

# generate update commands for Flannel
def genFlannelConfig(update_file, flannel_dict):
    base_cmd_line = "bpftool map update id "
    fw = open(update_file, 'w', encoding='utf-8')
    map_id = flannel_dict['map_id']
    cni0_mac = macToString(flannel_dict['cni0_mac'])
    for request_pair in flannel_dict['request_pair']:
        # new_cmd_line = base_cmd_line + map_id + " key " + ipToString(request_pair['remote_ip']) + ' ' + ipToString(request_pair['local']['ip']) + " value " + str(request_pair['local']['nic_num']) + ' 0 0 0 ' + macToString(request_pair['local']['mac']) + ' ' + cni0_mac + '\n'
        new_cmd_line = base_cmd_line + str(map_id) + " key " + ipToString(request_pair['remote_ip']) + ' ' + ipToString(request_pair['local']['ip']) + " value " + str(request_pair['local']['nic_num']) + ' 0 0 0 ' + cni0_mac + ' ' + macToString(request_pair['local']['mac']) + '\n'
        fw.write(new_cmd_line)
    fw.write("\n")
    fw.close()

# generate update commands for vNICs of pods
def genPodInstanceConfig(update_file, pod_dict):
    base_cmd_line = "bpftool map update id "
    fw = open(update_file, 'a', encoding='utf-8')
    change_mac_string = macToString(pod_dict['changed_mac']['src']['mac_addr']) + ' ' + macToString(pod_dict['changed_mac']['dst']['mac_addr'])
    target_nic_string = str(pod_dict['target_nic']['nic_num']) + ' 0 0 0'
    for pod in pod_dict['pods']:
        map_id = pod['map_id']
        for peer in pod['peer_ips']:
            new_cmd_line = base_cmd_line + str(map_id) + " key " + ipToString(pod['myip']) + ' ' + ipToString(peer) + " value " + target_nic_string + ' ' + change_mac_string + '\n'
            fw.write(new_cmd_line)
        fw.write("\n")
    fw.close()


def macToString(mac):
    byte_strings = mac.split(':')
    string16 = ""
    for byte_item in byte_strings:
        string16 += '0x' + byte_item + ' '
    return string16


def ipToString(ip):
    string16 = ip.replace('.', ' ')
    return string16


if __name__ == "__main__":
    update_file = "update_map.sh"
    config_dict = readYaml("config.yaml")
    genFlannelConfig(update_file, config_dict['flannel'])
    genPodInstanceConfig(update_file, config_dict['pod_instances'])
