import socket
import sys
import struct
import threading
import json
from my_ntwk_classes import Working_service, Working_host

eth_head_len = 14
filter_addrs = []
hosts = []
class_dict = {}

def send_to_gui():
    print "90"


def find_by_key(array, key):
    i = 0
    while(i != array.count()):
        if array[i].ip_addr == key:
            return i
    return None

def init_classess():
    ip_count = 2
    service_count = sys.argv[2 + sys.argv[2]]
    print service_count
    ports = sys.argv[3 + sys.argv[2]: 3 + sys.argv[2] + service_count]
    print ports
    while (ip_count != sys.argv[2]):
        filter_addrs.append(sys.argv[ip_count])
        buf = Working_host(service_count, ports, sys.argv[ip_count])
        hosts.append(buf)
        ip_count += 1


def backend_process(dest_ip, dest_port, packet_len):
    idx_1 = find_by_key(hosts, dest_ip)
    if idx_1 == None:
        return None
    idx_2 = find_by_key(hosts[idx_1].w_services, dest_port)
    if idx_2 == None:
        return None
    hosts[idx_1].w_services[idx_2].input_traffic += packet_len
    hosts[idx_1].input_traffic += packet_len
    return 1

def backend_deamon():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    except socket.error:
        print "Can't create socket"
        sys.exit()

    t = threading.Timer(1.0, send_to_gui)
    t.start()

    while True:
        packet = s.recvfrom(65535)
        packet_size = len(packet) / 1024 # Kbyte

        ip_header = packet[eth_head_len, eth_head_len + 20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        d_addr = socket.inet_ntoa(iph[9]);
        if d_addr not in filter_addrs:
            continue
        protocol = iph[6]
        if protocol not in (17, 6):
            continue
        if protocol == 17:
            udp_header = packet[eth_head_len + iph[0] * 4, eth_head_len + iph[0] * 4 + 8]
            udph = struct.unpack('!HHHH' , udp_header)
            udp_d_port = udph[1]
            backend_process(d_addr, udp_d_port, packet_size)

        if protocol == 6:
            tcp_header = packet[eth_head_len + iph[0] * 4, eth_head_len + iph[0] * 4 + 20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            tcp_d_port = tcph[1]
            backend_process(d_addr, tcp_d_port, packet_size)