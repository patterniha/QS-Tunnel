# todo: DNS(rd=1,qdcount=2,qd=DNSQR(qname="example.com", qtype="A") / DNSQR(qname="example.net", qtype="AAAA"))
# todo: test ips

import asyncio
import random
import socket
import json
import os
import sys

from data_handler import DataHandler
from utility.base32 import b32decode_nopad
from utility.dns import label_domain, handle_dns_request, \
    create_noerror_empty_response
from utility.packets import build_udp_payload_v4, build_ipv4_header, UDP_PROTO
from data_cap import get_crc32_bytes, get_chunk_data

ASSEMBLE_TIME = 5.0

RECV_QUERY_TYPE_INT = 1

CLIENT_ID_WIDTH = 10

DATA_OFFSET_WIDTH = 3

TOTAL_DATA_OFFSET = 1 << 5 * DATA_OFFSET_WIDTH
TOTAL_DATA_OFFSET_MINUS_ONE = TOTAL_DATA_OFFSET - 1


def create_v4_udp_dgram_socket(blocking: bool, bind_addr: None | tuple) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(blocking)
    if bind_addr is not None:
        s.bind(bind_addr)
    return s


with open(os.path.join(os.path.dirname(sys.argv[0]), "config_server.json")) as f:
    config = json.loads(f.read())

use_mode = config["mode"]
if use_mode == "1-1":
    client_id_bytes_len = 0
elif use_mode == "n-1":
    client_id_bytes_len = CLIENT_ID_WIDTH
else:
    sys.exit("invalid mode!")

wan_receive_bind_addr = ("0.0.0.0", int(config["receive_port"]))

recv_domain_labels = label_domain(config["recv_domain"].encode().lower())
len_recv_domain_labels = len(recv_domain_labels)

h_out_addr = (config["h_out_address"].rsplit(":", 1)[0], int(config["h_out_address"].rsplit(":", 1)[1]))

active_clients = {}

ip_id = random.randint(0, 65535)

raw_sender_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
raw_sender_sock.setblocking(False)
raw_sender_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)


# raw_sender_sock.bind((send_interface_ip,0))


async def client_h_recv(client_id, client_data_handler: DataHandler, client_sock: socket.socket,
                        client_send_info: list):
    loop = asyncio.get_running_loop()
    global ip_id
    if client_id == b"":
        timeout = None
    else:
        timeout = 30
    while True:
        try:
            data, addr = await asyncio.wait_for(loop.sock_recvfrom(client_sock, 65575), timeout=timeout)
            if not addr:
                raise ValueError("user_sock recv error no addr!")
        except Exception as e:
            client_sock.close()
            client_data_handler.cleaner_task.cancel()
            del active_clients[client_id]
            return
        if not data:
            continue
        if addr != h_out_addr:
            continue

        c_spoof_src_ip_bytes, c_spoof_src_port, client_ip_bytes, client_open_port, client_ip_str = client_send_info
        udp_header_and_data = build_udp_payload_v4(data, c_spoof_src_port, client_open_port, c_spoof_src_ip_bytes,
                                                   client_ip_bytes)
        ip_header = build_ipv4_header(len(udp_header_and_data), c_spoof_src_ip_bytes, client_ip_bytes, UDP_PROTO,
                                      128, ip_id,
                                      True)
        ip_id = (ip_id + 1) & 0xFFFF
        try:
            await loop.sock_sendto(raw_sender_sock, ip_header + udp_header_and_data,
                                   (client_ip_str, client_open_port))
        except Exception as e:
            print("raw_sock send error")
            client_sock.close()
            client_data_handler.cleaner_task.cancel()
            del active_clients[client_id]
            return


async def wan_recv():
    loop = asyncio.get_running_loop()
    wan_receive_socket = create_v4_udp_dgram_socket(False, wan_receive_bind_addr)
    while True:
        try:
            raw_data, addr_w = await loop.sock_recvfrom(wan_receive_socket, 65575)
            if not addr_w:
                raise ValueError("wan receive socket no addr!")
        except Exception as e:
            # print("wan receive socket recv error:", e)
            wan_receive_socket.close()
            while True:
                try:
                    wan_receive_socket = create_v4_udp_dgram_socket(False, wan_receive_bind_addr)
                except Exception as e:
                    print("wan receive socket create error:", e)
                    await asyncio.sleep(1)
                    continue
                break
            continue

        try:
            qid, qflags, all_labels, qtype, next_question = handle_dns_request(raw_data)
            if qtype != RECV_QUERY_TYPE_INT:
                raise ValueError("invalid qtype!")
            domain_labels = all_labels[-len_recv_domain_labels:]
            assert [label.lower() for label in domain_labels] == recv_domain_labels
        except Exception as e:
            print("receive invalid request:", raw_data)
            continue

        try:
            data_with_header = b"".join(all_labels[:-len_recv_domain_labels])
            if not data_with_header:
                raise ValueError("no header")
            client_id, data_offset, fragment_part, last_fragment, chunk_data = get_chunk_data(data_with_header,
                                                                                              DATA_OFFSET_WIDTH,
                                                                                              client_id_bytes_len)
            if not chunk_data:
                raise ValueError("no chunk data")
            only_info = False
            if fragment_part == 63 and not last_fragment:
                only_info = True
                info_data = b32decode_nopad(chunk_data)
                if len(info_data) != 12:
                    raise ValueError("invalid info!")
                client_ip_bytes = info_data[:4]
                client_open_port = int.from_bytes(info_data[4:6], byteorder="big")
                c_spoof_src_ip_bytes = info_data[6:10]
                c_spoof_src_port = int.from_bytes(info_data[10:12], byteorder="big")
                client_send_info = [c_spoof_src_ip_bytes, c_spoof_src_port, client_ip_bytes, client_open_port,
                                    socket.inet_ntop(socket.AF_INET, client_ip_bytes)]
                try:
                    _, _, _, client_save_send_info = active_clients[client_id]
                except KeyError:
                    client_data_handler = DataHandler(TOTAL_DATA_OFFSET, ASSEMBLE_TIME)
                    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    client_sock.setblocking(False)
                    t = asyncio.create_task(
                        client_h_recv(client_id, client_data_handler, client_sock, client_send_info))
                    active_clients[client_id] = (t, client_data_handler, client_sock, client_send_info)
                else:
                    if client_save_send_info != client_send_info:
                        for i in range(len(client_save_send_info)):
                            client_save_send_info[i] = client_send_info[i]





        except Exception:
            pass
        else:
            if not only_info:
                try:
                    client_h_recv_task, client_data_handler, client_sock, _ = active_clients[client_id]
                except KeyError:
                    pass
                else:
                    data = await client_data_handler.new_data_event(data_offset, fragment_part, last_fragment,
                                                                    chunk_data)
                    if data:
                        try:
                            data = b32decode_nopad(data)
                            final_data = data[:-4]
                            chksum = data[-4:]
                            assert final_data and len(chksum) == 4 and get_crc32_bytes(final_data,
                                                                                       b"") == chksum
                        except Exception as e:
                            print("data-error", e)
                        else:
                            try:
                                await loop.sock_sendto(client_sock, final_data, h_out_addr)
                            except Exception:
                                client_sock.close()
                                client_h_recv_task.cancel()
                                client_data_handler.cleaner_task.cancel()
                                del active_clients[client_id]

        response = create_noerror_empty_response(qid, qflags, raw_data[12:next_question])
        try:
            await loop.sock_sendto(wan_receive_socket, response, addr_w)
        except Exception as e:
            print("wan receive socket send error:", e)
            wan_receive_socket.close()
            while True:
                try:
                    wan_receive_socket = create_v4_udp_dgram_socket(False, wan_receive_bind_addr)
                except Exception as e:
                    print("wan receive socket create error:", e)
                    await asyncio.sleep(1)
                    continue
                break


async def main():
    wait_list = [asyncio.create_task(wan_recv())]
    print("started...")
    await asyncio.wait(wait_list, return_when=asyncio.FIRST_COMPLETED)


asyncio.run(main())
