from struct import pack

from utility.numba_checksum import checksum

UDP_PROTO = 17
TCP_PROTO = 6
IPV4_VER_IHL = 0x45  # (4 << 4) | 5
IPV6_VER_TC_FL_BASE = 0x60000000  # (6 << 28)
UDP_PSEUDO_V6_TAIL = b"\x00\x00\x00\x11"  # zeros + next-header (UDP=17)
TCP_PSEUDO_V6_TAIL = b"\x00\x00\x00\x06"  # zeros + next-header (TCP=6)


def build_tcp_payload_v4(
        data: bytes,
        src_port: int,
        dst_port: int,
        seq: int,
        ack: int,
        flags: int,
        window: int,
        tcp_options: bytes,
        src_ip_packed: bytes,
        dst_ip_packed: bytes,
        urgent_ptr: int = 0,
) -> bytes:
    if len(tcp_options) & 3:
        raise ValueError("tcp_options length must be a multiple of 4 bytes")

    data_offset = 5 + (len(tcp_options) // 4)  # 32-bit words
    offset_flags = (data_offset << 12) | (flags & 0x01FF)

    tcp_len = data_offset * 4 + len(data)

    tcp_header = pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_flags,
        window,
        0,  # checksum placeholder
        urgent_ptr,
    )

    pseudo_header = pack(
        "!4s4sBBH",
        src_ip_packed,
        dst_ip_packed,
        0,
        TCP_PROTO,
        tcp_len,
    )

    tcp_checksum = checksum(pseudo_header + tcp_header + tcp_options + data)
    tcp_header = pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_flags,
        window,
        tcp_checksum,
        urgent_ptr,
    )

    return tcp_header + tcp_options + data


def build_tcp_payload_v6(
        data: bytes,
        src_port: int,
        dst_port: int,
        seq: int,
        ack: int,
        flags: int,
        window: int,
        tcp_options: bytes,
        src_ip_packed: bytes,
        dst_ip_packed: bytes,
        urgent_ptr: int = 0,
) -> bytes:
    if len(tcp_options) & 3:
        raise ValueError("tcp_options length must be a multiple of 4 bytes")

    data_offset = 5 + (len(tcp_options) // 4)
    offset_flags = (data_offset << 12) | (flags & 0x01FF)

    tcp_len = data_offset * 4 + len(data)

    tcp_header = pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_flags,
        window,
        0,
        urgent_ptr,
    )

    pseudo_header = (
            src_ip_packed +
            dst_ip_packed +
            pack("!I", tcp_len) +
            TCP_PSEUDO_V6_TAIL
    )

    tcp_checksum = checksum(pseudo_header + tcp_header + tcp_options + data)
    tcp_header = pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_flags,
        window,
        tcp_checksum,
        urgent_ptr,
    )

    return tcp_header + tcp_options + data


def build_udp_payload_v4(
        data: bytes,
        src_port: int,
        dst_port: int,
        src_ip_packed: bytes,
        dst_ip_packed: bytes,
) -> bytes:
    udp_len = 8 + len(data)
    udp_header = pack("!HHHH", src_port, dst_port, udp_len, 0)

    pseudo_header = pack(
        "!4s4sBBH",
        src_ip_packed,
        dst_ip_packed,
        0,
        UDP_PROTO,
        udp_len,
    )

    udp_checksum = checksum(pseudo_header + udp_header + data)
    if udp_checksum == 0:
        udp_checksum = 0xFFFF

    udp_header = pack("!HHHH", src_port, dst_port, udp_len, udp_checksum)
    return udp_header + data


def build_udp_payload_v6(
        data: bytes,
        src_port: int,
        dst_port: int,
        src_ip_packed: bytes,
        dst_ip_packed: bytes,
) -> bytes:
    udp_len = 8 + len(data)
    udp_header = pack("!HHHH", src_port, dst_port, udp_len, 0)

    pseudo_header = (
            src_ip_packed +
            dst_ip_packed +
            pack("!I", udp_len) +
            UDP_PSEUDO_V6_TAIL
    )

    udp_checksum = checksum(pseudo_header + udp_header + data)
    if udp_checksum == 0:
        udp_checksum = 0xFFFF

    udp_header = pack("!HHHH", src_port, dst_port, udp_len, udp_checksum)
    return udp_header + data


def build_ipv4_header(
        payload_len: int,
        src_ip_packed: bytes,
        dst_ip_packed: bytes,
        proto: int,
        ttl: int = 64,
        ip_id: int = 0,
        dont_fragment: bool = False,
        frag_offset: int = 0,
        more_fragments: bool = False,
) -> bytes:
    dscp_ecn = 0
    total_len = 20 + payload_len

    flags = 0x2 if dont_fragment else 0x0
    if more_fragments:
        flags |= 0x1
    flags_frag = (flags << 13) | (frag_offset & 0x1FFF)

    hdr_checksum = 0
    header = pack(
        "!BBHHHBBH4s4s",
        IPV4_VER_IHL,
        dscp_ecn,
        total_len,
        ip_id,
        flags_frag,
        ttl,
        proto,
        hdr_checksum,
        src_ip_packed,
        dst_ip_packed,
    )
    hdr_checksum = checksum(header)

    return pack(
        "!BBHHHBBH4s4s",
        IPV4_VER_IHL,
        dscp_ecn,
        total_len,
        ip_id,
        flags_frag,
        ttl,
        proto,
        hdr_checksum,
        src_ip_packed,
        dst_ip_packed,
    )


def build_ipv6_header(
        payload_len: int,
        src_ip_packed: bytes,
        dst_ip_packed: bytes,
        next_header: int,  # proto
        hop_limit: int = 64,
        flow_label: int = 0,
) -> bytes:
    flow_label &= 0xFFFFF
    ver_tc_fl = IPV6_VER_TC_FL_BASE | flow_label
    return pack(
        "!IHBB16s16s",
        ver_tc_fl,
        payload_len,
        next_header,
        hop_limit,
        src_ip_packed,
        dst_ip_packed,
    )
