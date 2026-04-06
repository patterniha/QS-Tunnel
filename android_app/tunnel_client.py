import asyncio
import random
import socket
import hashlib
import os

from utility.dns import encode_qname, build_dns_query, insert_dots
from utility.base32 import number_to_base32_lower, b32encode_nopad_lower
from data_cap import get_base32_final_domains, get_chunk_len, bytes_xor

CLIENT_ID_WIDTH = 7

PACKETS_QUEUE_SIZE = 1024

DATA_OFFSET_WIDTH = 3

TOTAL_CLIENT_IDS = 1 << 5 * CLIENT_ID_WIDTH

TOTAL_DATA_OFFSET = 1 << 5 * DATA_OFFSET_WIDTH
TOTAL_DATA_OFFSET_MINUS_ONE = TOTAL_DATA_OFFSET - 1


def _create_v4_udp_dgram_socket(blocking: bool, bind_addr: tuple | None) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(blocking)
    if bind_addr is not None:
        s.bind(bind_addr)
    return s


class TunnelClient:
    """Wrapper around main_client.py logic that can be started and stopped."""

    def __init__(self, config: dict, log_callback=None):
        self.config = config
        self.log_callback = log_callback
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._send_sock_list: list[socket.socket] = []
        self._h_inbound_socket: socket.socket | None = None
        self._wan_main_socket: socket.socket | None = None
        self._queues_list: list[asyncio.Queue] = []
        self._last_h_addr: tuple | None = None
        self._last_wan_recv_time: float | None = None

    def _log(self, msg: str):
        if self.log_callback:
            self.log_callback(str(msg))

    def _validate_config(self):
        config = self.config
        if not config.get("dns_ips"):
            raise ValueError("dns_ips must not be empty")
        if not config.get("send_domain"):
            raise ValueError("send_domain must not be empty")
        if not config.get("fake_send_ip"):
            raise ValueError("fake_send_ip must not be empty")
        mode = config.get("mode", "")
        if mode not in ("1-1", "n-1"):
            raise ValueError("mode must be '1-1' or 'n-1'")

    @property
    def is_running(self) -> bool:
        return self._running

    async def start(self):
        """Start the tunnel client. Blocks until stopped or an error occurs."""
        self._validate_config()
        config = self.config
        self._running = True

        send_query_type_int = config["send_query_type_int"]
        info_encryption_pass = hashlib.sha256(config["info_encryption_pass"].encode()).digest()

        use_mode = config["mode"]
        if use_mode == "1-1":
            client_id_bytes = b""
        else:
            client_id_bytes = number_to_base32_lower(random.randint(0, TOTAL_CLIENT_IDS - 1), CLIENT_ID_WIDTH)

        self._send_sock_list = []
        for _ in range(config.get("send_sock_numbers", 64)):
            self._send_sock_list.append(_create_v4_udp_dgram_socket(False, ("0.0.0.0", 0)))

        dns_ips = config["dns_ips"]
        self._queues_list = []

        h_in_address = config["h_in_address"]
        h_inbound_bind_addr = (h_in_address.rsplit(":", 1)[0], int(h_in_address.rsplit(":", 1)[1]))
        self._h_inbound_socket = _create_v4_udp_dgram_socket(False, h_inbound_bind_addr)

        max_encoded_domain_len = config["max_domain_len"] + 2
        if max_encoded_domain_len > 255:
            raise ValueError("the maximum domain length is 253 bytes")
        max_sub_len = config["max_sub_len"]
        if max_sub_len > 63:
            raise ValueError("max_sub_len cannot be greater than 63!")
        tries = config.get("retries", 1) + 1
        send_domain_encode_qname = encode_qname(config["send_domain"].encode().lower())
        chunk_len = get_chunk_len(max_encoded_domain_len, len(send_domain_encode_qname), max_sub_len,
                                  DATA_OFFSET_WIDTH, len(client_id_bytes))

        self._wan_main_socket = _create_v4_udp_dgram_socket(False, ("0.0.0.0", 0))
        wan_main_socket_port = int(self._wan_main_socket.getsockname()[1])

        fake_send_ip = config["fake_send_ip"]
        fake_send_port = int(config.get("fake_send_port", 443))

        # Get public IP
        my_public_ip = config.get("my_public_ip", "ezping")
        if my_public_ip == "ezping":
            my_public_ip = await self._get_public_ip("https://ezping.ir/geoip", "ip")
            self._log(f"Public IP: {my_public_ip}")

        loop = asyncio.get_running_loop()

        # Initial NAT punch
        for _ in range(3):
            data = os.urandom(random.randint(257, 499))
            await loop.sock_sendto(self._wan_main_socket, data, (fake_send_ip, fake_send_port))
            await asyncio.sleep(0.001)

        # Create queues and sender tasks
        self._tasks = []
        for _ in dns_ips:
            queue = asyncio.Queue(maxsize=PACKETS_QUEUE_SIZE)
            self._queues_list.append(queue)
            self._tasks.append(asyncio.create_task(self._wan_send_from_queue(queue)))

        self._tasks.append(asyncio.create_task(
            self._h_recv(my_public_ip, send_query_type_int, info_encryption_pass,
                         client_id_bytes, dns_ips, h_inbound_bind_addr,
                         max_encoded_domain_len, max_sub_len, tries,
                         send_domain_encode_qname, chunk_len,
                         wan_main_socket_port, fake_send_ip, fake_send_port)))
        self._tasks.append(asyncio.create_task(self._wan_recv(h_inbound_bind_addr)))
        self._tasks.append(asyncio.create_task(self._nat_keep_alive(fake_send_ip, fake_send_port)))

        self._log("Tunnel started")

        try:
            done, _ = await asyncio.wait(self._tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                if not task.cancelled():
                    exc = task.exception()
                    if exc:
                        self._log(f"Task error: {exc}")
        except asyncio.CancelledError:
            pass

    async def stop(self):
        """Stop the tunnel client and clean up all resources."""
        self._running = False

        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self._queues_list.clear()

        for sock in self._send_sock_list:
            try:
                sock.close()
            except Exception:
                pass
        self._send_sock_list.clear()

        if self._h_inbound_socket:
            try:
                self._h_inbound_socket.close()
            except Exception:
                pass
            self._h_inbound_socket = None

        if self._wan_main_socket:
            try:
                self._wan_main_socket.close()
            except Exception:
                pass
            self._wan_main_socket = None

        self._last_h_addr = None
        self._last_wan_recv_time = None
        self._log("Tunnel stopped")

    async def _get_public_ip(self, url: str, ip_name: str):
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                response.raise_for_status()
                data = await response.json()
                return data.get(ip_name)

    async def _wan_send_from_queue(self, queue: asyncio.Queue):
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                send_socks_datas, send_ip_str, entry_time, curr_try, contain_info = await asyncio.wait_for(
                    queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            if loop.time() - entry_time > 1:
                continue

            if curr_try & 1 == 0:
                iter_range = range(len(send_socks_datas))
            else:
                if contain_info:
                    iter_range = range(0, -len(send_socks_datas), -1)
                else:
                    iter_range = range(len(send_socks_datas) - 1, -1, -1)

            for i in iter_range:
                if not self._running:
                    return
                send_sock_index, send_sock, data = send_socks_datas[i]
                try:
                    await loop.sock_sendto(send_sock, data, (send_ip_str, 53))
                except Exception as e:
                    self._log(f"Send error: {e}")
                    send_sock.close()
                    while self._running:
                        await asyncio.sleep(1)
                        if self._send_sock_list[send_sock_index] != send_sock:
                            break
                        try:
                            self._send_sock_list[send_sock_index] = _create_v4_udp_dgram_socket(False, ("0.0.0.0", 0))
                        except Exception as e:
                            self._log(f"Socket recreate error: {e}")
                            continue
                        break
                    break
                await asyncio.sleep(0.0000001)

    async def _h_recv(self, my_public_ip, send_query_type_int, info_encryption_pass,
                      client_id_bytes, dns_ips, h_inbound_bind_addr,
                      max_encoded_domain_len, max_sub_len, tries,
                      send_domain_encode_qname, chunk_len,
                      wan_main_socket_port, fake_send_ip, fake_send_port):
        loop = asyncio.get_running_loop()
        send_sock_index = random.randint(0, len(self._send_sock_list) - 1)
        query_id = random.randint(0, 65535)
        data_offset = random.randint(0, TOTAL_DATA_OFFSET_MINUS_ONE)
        info_offset = random.randint(0, TOTAL_DATA_OFFSET_MINUS_ONE)
        send_ip_index = random.randint(0, len(dns_ips) - 1)
        queue_index = random.randint(0, len(self._queues_list) - 1)

        info_raw_data = b32encode_nopad_lower(bytes_xor(
            socket.inet_pton(socket.AF_INET, my_public_ip) + wan_main_socket_port.to_bytes(2, byteorder="big") +
            socket.inet_pton(socket.AF_INET, fake_send_ip) + fake_send_port.to_bytes(2, byteorder="big"),
            info_encryption_pass))
        info_raw_header_data = b"78" + info_raw_data

        while self._running:
            use_h_inbound_socket = self._h_inbound_socket
            try:
                raw_data, addr_h = await asyncio.wait_for(
                    loop.sock_recvfrom(use_h_inbound_socket, 65575), timeout=1.0)
                if not addr_h:
                    raise ValueError("h inbound socket no addr!")
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self._log(f"Inbound recv error: {e}")
                use_h_inbound_socket.close()
                while self._running:
                    if self._h_inbound_socket != use_h_inbound_socket:
                        break
                    try:
                        self._h_inbound_socket = _create_v4_udp_dgram_socket(False, h_inbound_bind_addr)
                    except Exception as e:
                        self._log(f"Inbound recreate error: {e}")
                        await asyncio.sleep(1)
                        continue
                    break
                continue

            if not raw_data:
                continue

            final_domains = get_base32_final_domains(raw_data, data_offset, chunk_len, send_domain_encode_qname,
                                                     max_sub_len, DATA_OFFSET_WIDTH, max_encoded_domain_len,
                                                     client_id_bytes)
            if not final_domains:
                continue
            data_offset = (data_offset + 1) & TOTAL_DATA_OFFSET_MINUS_ONE

            if self._last_h_addr != addr_h:
                self._last_h_addr = addr_h
                self._log(f"Data sent to: {addr_h}")

            send_socks_datas = []
            contain_info = False
            if (self._last_wan_recv_time is None) or (loop.time() - self._last_wan_recv_time > 25):
                contain_info = True
                sub_info = (client_id_bytes + number_to_base32_lower(info_offset, DATA_OFFSET_WIDTH) +
                            info_raw_header_data)
                info_offset = (info_offset + 1) & TOTAL_DATA_OFFSET_MINUS_ONE
                info_domain_bytes = insert_dots(sub_info, max_sub_len) + send_domain_encode_qname

                send_socks_datas.append((send_sock_index, self._send_sock_list[send_sock_index],
                                         build_dns_query(info_domain_bytes, query_id, send_query_type_int)))
                send_sock_index = (send_sock_index + 1) % len(self._send_sock_list)
                query_id = (query_id + 1) & 0xFFFF

            for final_domain in final_domains:
                send_socks_datas.append(
                    (send_sock_index, self._send_sock_list[send_sock_index],
                     build_dns_query(final_domain, query_id, send_query_type_int)))
                send_sock_index = (send_sock_index + 1) % len(self._send_sock_list)
                query_id = (query_id + 1) & 0xFFFF

            curr_try = 0
            while curr_try < tries:
                try:
                    self._queues_list[queue_index].put_nowait(
                        (send_socks_datas, dns_ips[send_ip_index], loop.time(), curr_try, contain_info))
                except asyncio.QueueFull:
                    pass
                send_ip_index = (send_ip_index + 1) % len(dns_ips)
                queue_index = (queue_index + 1) % len(self._queues_list)
                curr_try += 1

    async def _wan_recv(self, h_inbound_bind_addr):
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                data, addr_w = await asyncio.wait_for(
                    loop.sock_recvfrom(self._wan_main_socket, 65575), timeout=1.0)
                if not addr_w:
                    raise ValueError("wan receive socket no addr!")
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self._log(f"WAN recv error: {e}")
                raise

            if not data:
                continue

            if self._last_h_addr is None:
                continue

            self._last_wan_recv_time = loop.time()

            use_h_inbound_socket = self._h_inbound_socket
            try:
                await loop.sock_sendto(use_h_inbound_socket, data, self._last_h_addr)
            except Exception as e:
                self._log(f"Inbound send error: {e}")
                use_h_inbound_socket.close()
                while self._running:
                    if self._h_inbound_socket != use_h_inbound_socket:
                        break
                    try:
                        self._h_inbound_socket = _create_v4_udp_dgram_socket(False, h_inbound_bind_addr)
                    except Exception as e:
                        self._log(f"Inbound recreate error: {e}")
                        await asyncio.sleep(1)
                        continue
                    break

    async def _nat_keep_alive(self, fake_send_ip, fake_send_port):
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                await asyncio.sleep(2)
                if not self._running:
                    return
                data = os.urandom(random.randint(257, 499))
                await loop.sock_sendto(self._wan_main_socket, data, (fake_send_ip, fake_send_port))
            except Exception as e:
                self._log(f"NAT keepalive error: {e}")
                raise
