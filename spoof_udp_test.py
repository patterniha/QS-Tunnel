import random
import socket

from utility.packets import build_ipv4_header, build_udp_payload_v4, UDP_PROTO

########### CONFIGURATION:

SPOOFED_SRC_IP = "1.1.1.1"
DST_IP = "2.2.2.2"
UDP_SRC_PORT = 443
UDP_DST_PORT = 60443
DATA = b"1234"

##########################

src_ip_bytes = socket.inet_pton(socket.AF_INET, SPOOFED_SRC_IP)
dst_ip_bytes = socket.inet_pton(socket.AF_INET, DST_IP)

raw_sender_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
raw_sender_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

udp_header_and_data = build_udp_payload_v4(DATA, UDP_SRC_PORT, UDP_DST_PORT,
                                           src_ip_bytes,
                                           dst_ip_bytes)

ip_header = build_ipv4_header(len(udp_header_and_data), src_ip_bytes, dst_ip_bytes, UDP_PROTO, 128,
                              random.randint(0, 65535), True)

raw_sender_sock.sendto(ip_header + udp_header_and_data, (DST_IP, UDP_DST_PORT))
