# todo: DNS(rd=1,qdcount=2,qd=DNSQR(qname="example.com", qtype="A") / DNSQR(qname="example.net", qtype="AAAA"))
# todo: test ips

import asyncio
import random
import socket
import json
import os
import sys
import time

import aiohttp

from utility.dns import encode_qname, build_dns_query, insert_dots
from utility.base32 import number_to_base32_lower, b32encode_nopad_lower
from data_cap import get_base32_final_domains, get_chunk_len

CLIENT_ID_WIDTH = 10

PACKETS_QUEUE_SIZE = 1024

DATA_OFFSET_WIDTH = 3

SEND_QUERY_TYPE_INT = 1

TOTAL_CLIENT_IDS = 1 << 5 * CLIENT_ID_WIDTH

TOTAL_DATA_OFFSET = 1 << 5 * DATA_OFFSET_WIDTH
TOTAL_DATA_OFFSET_MINUS_ONE = TOTAL_DATA_OFFSET - 1

TIME_RESOLUTION = time.get_clock_info("perf_counter").resolution


def create_v4_udp_dgram_socket(blocking: bool, bind_addr: None | tuple) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(blocking)
    if bind_addr is not None:
        s.bind(bind_addr)
    return s


async def exact_sleep(delay: float):
    loop = asyncio.get_running_loop()
    now = loop.time()
    while True:
        await asyncio.sleep(TIME_RESOLUTION)
        if loop.time() - now > delay:
            return


with open(os.path.join(os.path.dirname(sys.argv[0]), "config_client.json")) as f:
    config = json.loads(f.read())

use_mode = config["mode"]
if use_mode == "1-1":
    client_id_bytes = b""
elif use_mode == "n-1":
    client_id_bytes = number_to_base32_lower(random.randint(0, TOTAL_CLIENT_IDS - 1), CLIENT_ID_WIDTH)
else:
    sys.exit("invalid mode!")

packets_send_interval = config["packets_send_interval"]

if ((sys.platform == "win32") and (packets_send_interval < 0.1)) or (packets_send_interval < 0.001):
    PACKETS_SEND_SLEEP = exact_sleep
else:
    PACKETS_SEND_SLEEP = asyncio.sleep

send_sock_list = []
# ulimit -n 32768
for _ in range(config["send_sock_numbers"]):
    send_sock_list.append(create_v4_udp_dgram_socket(False, ("0.0.0.0", 0)))

dns_ips = config["dns_ips"]
queues_list: list[asyncio.Queue] = []

h_inbound_bind_addr = (config["h_in_address"].rsplit(":", 1)[0], int(config["h_in_address"].rsplit(":", 1)[1]))
h_inbound_socket = create_v4_udp_dgram_socket(False, h_inbound_bind_addr)

max_encoded_domain_len = config["max_domain_len"] + 2
if max_encoded_domain_len > 255:
    sys.exit("the maximum domain length is 253 bytes")
max_sub_len = config["max_sub_len"]
if max_sub_len > 63:
    sys.exit("max_sub_len cannot be greater than 63!")
tries = config["retries"] + 1
send_domain_encode_qname = encode_qname(config["send_domain"].encode().lower())
chunk_len = get_chunk_len(max_encoded_domain_len, len(send_domain_encode_qname), max_sub_len, DATA_OFFSET_WIDTH,
                          len(client_id_bytes))

last_h_addr: tuple | None = None

wan_main_socket = create_v4_udp_dgram_socket(False, ("0.0.0.0", 0))
wan_main_socket_port = int(wan_main_socket.getsockname()[1])

fake_send_ip = config["fake_send_ip"]
fake_send_port = int(config["fake_send_port"])

last_wan_recv_time: float | None = None


async def wan_send_from_queue(queue: asyncio.Queue):
    loop = asyncio.get_running_loop()
    while True:
        send_socks_datas, send_ip_str, entry_time, curr_try, contain_info = await queue.get()
        if loop.time() - entry_time > 1:
            continue  # drop

        if curr_try & 1 == 0:
            iter_range = range(len(send_socks_datas))
        else:
            if contain_info:
                iter_range = range(0, -len(send_socks_datas), -1)
            else:
                iter_range = range(len(send_socks_datas) - 1, -1, -1)

        for i in iter_range:
            send_sock_index, send_sock, data = send_socks_datas[i]
            try:
                await loop.sock_sendto(send_sock, data, (send_ip_str, 53))
            except Exception as e:
                print("wan_send_sock send error:", e, send_ip_str, send_sock)
                send_sock.close()
                while True:
                    await asyncio.sleep(1)
                    if send_sock_list[send_sock_index] != send_sock:
                        break
                    try:
                        send_sock_list[send_sock_index] = create_v4_udp_dgram_socket(False, ("0.0.0.0", 0))
                    except Exception as e:
                        print("wan_send_sock create error:", e)
                        continue
                    break
                break
            await PACKETS_SEND_SLEEP(packets_send_interval)


async def h_recv(my_public_ip: str):
    loop = asyncio.get_running_loop()
    global h_inbound_socket
    global last_h_addr
    send_sock_index = random.randint(0, len(send_sock_list) - 1)
    query_id = random.randint(0, 65535)
    data_offset = random.randint(0, TOTAL_DATA_OFFSET_MINUS_ONE)
    info_offset = random.randint(0, TOTAL_DATA_OFFSET_MINUS_ONE)
    send_ip_index = random.randint(0, len(dns_ips) - 1)
    queue_index = random.randint(0, len(queues_list) - 1)

    info_raw_data = b32encode_nopad_lower(
        socket.inet_pton(socket.AF_INET, my_public_ip) + wan_main_socket_port.to_bytes(2,
                                                                                       byteorder="big") + socket.inet_pton(
            socket.AF_INET, fake_send_ip) + fake_send_port.to_bytes(2, byteorder="big"))
    info_raw_header_data = b"78" + info_raw_data

    while True:
        use_h_inbound_socket = h_inbound_socket
        try:
            raw_data, addr_h = await loop.sock_recvfrom(use_h_inbound_socket, 65575)
            if not addr_h:
                raise ValueError("h inbound socket no addr!")
        except Exception as e:
            print("h_inbound_socket recv error:", e)
            use_h_inbound_socket.close()
            while True:
                if h_inbound_socket != use_h_inbound_socket:
                    break
                try:
                    h_inbound_socket = create_v4_udp_dgram_socket(False, h_inbound_bind_addr)
                except Exception as e:
                    print("h_inbound_socket create error:", e)
                    await asyncio.sleep(1)
                    continue
                break
            continue

        if not raw_data:
            continue

        final_domains = get_base32_final_domains(raw_data, data_offset, chunk_len, send_domain_encode_qname,
                                                 max_sub_len, b"", DATA_OFFSET_WIDTH, max_encoded_domain_len,
                                                 client_id_bytes)
        if not final_domains:
            continue
        data_offset = (data_offset + 1) & TOTAL_DATA_OFFSET_MINUS_ONE

        if last_h_addr != addr_h:
            last_h_addr = addr_h
            print("the received data is sent to:", addr_h)

        send_socks_datas = []
        contain_info = False
        if (last_wan_recv_time is None) or (loop.time() - last_wan_recv_time > 25):
            ###
            contain_info = True
            sub_info = number_to_base32_lower(info_offset, DATA_OFFSET_WIDTH) + info_raw_header_data
            info_offset = (info_offset + 1) & TOTAL_DATA_OFFSET_MINUS_ONE
            info_domain_bytes = insert_dots(sub_info, max_sub_len) + send_domain_encode_qname

            send_socks_datas.append((send_sock_index, send_sock_list[send_sock_index],
                                     build_dns_query(info_domain_bytes, query_id, SEND_QUERY_TYPE_INT)))
            send_sock_index = (send_sock_index + 1) % len(send_sock_list)
            query_id = (query_id + 1) & 0xFFFF
            ###
        for final_domain in final_domains:
            send_socks_datas.append(
                (send_sock_index, send_sock_list[send_sock_index],
                 build_dns_query(final_domain, query_id, SEND_QUERY_TYPE_INT)))
            send_sock_index = (send_sock_index + 1) % len(send_sock_list)
            query_id = (query_id + 1) & 0xFFFF

        curr_try = 0
        while curr_try < tries:
            try:
                queues_list[queue_index].put_nowait(
                    (send_socks_datas, dns_ips[send_ip_index], loop.time(), curr_try, contain_info))
            except asyncio.QueueFull:
                pass
            send_ip_index = (send_ip_index + 1) % len(dns_ips)
            queue_index = (queue_index + 1) % len(queues_list)
            curr_try += 1


async def wan_recv():
    loop = asyncio.get_running_loop()
    global h_inbound_socket
    global last_wan_recv_time
    while True:
        try:
            data, addr_w = await loop.sock_recvfrom(wan_main_socket, 65575)
            if not addr_w:
                raise ValueError("wan receive socket no addr!")
        except Exception as e:
            print("wan receive socket recv error:", e)
            raise

        if not data:
            continue

        if last_h_addr is None:
            continue

        last_wan_recv_time = loop.time()

        use_h_inbound_socket = h_inbound_socket
        try:
            await loop.sock_sendto(use_h_inbound_socket, data, last_h_addr)
        except Exception as e:
            print("h_inbound_socket send error:", e)
            use_h_inbound_socket.close()
            while True:
                if h_inbound_socket != use_h_inbound_socket:
                    break
                try:
                    h_inbound_socket = create_v4_udp_dgram_socket(False, h_inbound_bind_addr)
                except Exception as e:
                    print("h_inbound_socket create error:", e)
                    await asyncio.sleep(1)
                    continue
                break


async def nat_keep_alive():
    loop = asyncio.get_running_loop()
    while True:
        try:
            await asyncio.sleep(2)
            data = os.urandom(random.randint(257, 499))
            await loop.sock_sendto(wan_main_socket, data, (fake_send_ip, fake_send_port))
        except Exception as e:
            print("nat puncher send error:", e)
            raise


async def get_public_ip_from_json_api(url: str, ip_name: str):
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=5) as response:
            response.raise_for_status()
            data = await response.json()
            return data.get(ip_name)


async def main():
    loop = asyncio.get_running_loop()
    my_public_ip = config["my_public_ip"]
    if my_public_ip == "ezping":
        my_public_ip = await get_public_ip_from_json_api("https://ezping.ir/geoip", "ip")
    for _ in range(3):
        data = os.urandom(random.randint(257, 499))
        await loop.sock_sendto(wan_main_socket, data, (fake_send_ip, fake_send_port))
        await asyncio.sleep(0.001)

    wait_list = []
    for _ in dns_ips:
        queue = asyncio.Queue(maxsize=PACKETS_QUEUE_SIZE)
        queues_list.append(queue)
        wait_list.append(asyncio.create_task(wan_send_from_queue(queue)))

    wait_list.append(asyncio.create_task(h_recv(my_public_ip)))
    wait_list.append(asyncio.create_task(wan_recv()))
    wait_list.append(asyncio.create_task(nat_keep_alive()))
    print("started...")
    await asyncio.wait(wait_list, return_when=asyncio.FIRST_COMPLETED)


asyncio.run(main())
