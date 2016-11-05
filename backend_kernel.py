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

class my_json_object:
	def toJSON(self):
		return json.dumps(self, default=lambda o: o.__dict__,sort_keys=True, indent=4)

def clear_all():
	i = 0
	global host_count
	while(i != host_count):
		j = 0
		hosts[i].input_traffic = 0
		global service_count
		while(j != service_count):
			hosts[i].w_services[j].input_traffic = 0
			j+=1
		i+=1
def json_encoding(encoded_class):
	json_view = my_json_object()
	json_view.is_active = encoded_class.is_active
	json_view.ip_addr = encoded_class.ip_addr
	json_view.input_traffic = encoded_class.input_traffic

	i = 0
	global service_count
	json_view.w_services = []
	while(i != service_count):
		tmp = my_json_object()
		tmp.is_active = encoded_class.w_services[i].is_active
		tmp.input_traffic = encoded_class.w_services[i].input_traffic
		tmp.port = encoded_class.w_services[i].port
		json_view.w_services.append(tmp)
		tmp = None
		i += 1
	return json_view

def send_to_gui():
	i = 0
	global host_count
	while(i < host_count):
		print(json_encoding(hosts[i]).toJSON())
		i+=1
	clear_all()

def find_by_ip(array, key):
	i = 0
	global host_count
	while(i != host_count):
		if array[i].ip_addr == key:
			return i
		i+=1
	return None
def find_by_port(array, key):
	i = 0
	global service_count
	while(i != service_count):
		if array[i].port == key:
			return i
		i+=1
	return None

def init_classess():
	i = 0
	global host_count
	host_count = int(sys.argv[1])
	global service_count
	service_count = int(sys.argv[2 + host_count])
	print "host_count", host_count
	print "service_count", service_count
	ports = sys.argv[3 + host_count: 3 + host_count + service_count]
	print "ports", ports
	while (i != host_count):
		filter_addrs.append(sys.argv[i + 2])
		buf = Working_host(service_count, ports, sys.argv[i + 2])
		hosts.append(buf)
		i += 1


def backend_process(dest_ip, dest_port, packet_len):
	idx_1 = find_by_ip(hosts, dest_ip)
	if idx_1 == None:
		return None
	idx_2 = find_by_port(hosts[idx_1].w_services, dest_port)
	if idx_2 == None:
		return None
	hosts[idx_1].w_services[idx_2].input_traffic += packet_len
	hosts[idx_1].input_traffic += packet_len
	return 1

def my_timer(n):
	t = threading.Timer(float(n), send_to_gui)
	while True:
		t.start()
		t.join()

ETH_P_ALL = 0x0003
def backend_deamon():
	try:
		s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
	except socket.error, msg:
		print "Can't create socket"
		print msg[0]
		print msg[1]
		sys.exit()

	my_thread = threading.Thread(target=my_timer, args=["1.0"]) #change time self
	my_thread.start()

	while True:

		frame = s.recvfrom(65535)
		packet = frame[0]
		#print (packet)
		packet_size = len(packet)  # Kbyte

		#print ("Size:",packet_size)

		ip_header = packet[eth_head_len : eth_head_len + 20]
		iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
		d_addr = socket.inet_ntoa(iph[9])
		#print ("Dest ip:", d_addr)
		if d_addr not in filter_addrs:
			continue
		protocol = iph[6]
		iph_len = iph[0]&0xF
#	print iph_len, iph_len
		if protocol not in (17, 6):
			continue
		if protocol == 17:
			udp_header = packet[eth_head_len + iph_len * 4: eth_head_len + iph_len * 4 + 8]
			udph = struct.unpack('!HHHH' , udp_header)
			udp_d_port = udph[1]
			print ("Udp, port ", udp_d_port)
			backend_process(d_addr, udp_d_port, packet_size)

		if protocol == 6:
			tcp_header = packet[eth_head_len + iph_len * 4: eth_head_len + iph_len * 4 + 20]
			tcph = struct.unpack('!HHLLBBHHH', tcp_header)
			tcp_d_port = tcph[1]
			print ("Tcp, port ", tcp_d_port)
			backend_process(d_addr, tcp_d_port, packet_size)

service_count = 0
host_count = 0
init_classess()
backend_deamon()

