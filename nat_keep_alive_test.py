import os
import random
import socket
import time

########### CONFIGURATION:

SPOOFED_DST_IP = "1.1.1.1"
UDP_SRC_PORT = 60443
UDP_DST_PORT = 443

##########################

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", UDP_SRC_PORT))

for _ in range(3):
    data = os.urandom(random.randint(257, 499))
    s.sendto(data, (SPOOFED_DST_IP, UDP_DST_PORT))
    time.sleep(0.001)

while True:
    time.sleep(2)
    data = os.urandom(random.randint(257, 499))
    s.sendto(data, (SPOOFED_DST_IP, UDP_DST_PORT))
    