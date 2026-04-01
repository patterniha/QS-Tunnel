import sys
import zlib

from utility.base32 import b32encode_nopad_lower, BASE32_LIST_LOWER, number_to_base32_lower, base32_to_number, \
    BASE32_LOOKUP
from utility.dns import insert_dots


def get_crc32_bytes(data: bytes, chksum_pass: bytes) -> bytes:
    if chksum_pass:
        return zlib.crc32(data + chksum_pass).to_bytes(4, byteorder="big")
    return zlib.crc32(data).to_bytes(4, byteorder="big")


def compute_max_m(s: int, max_allowed: int) -> int:
    """
    Find maximum m such that: m + ⌈m / s⌉ ≤ max_allowed
    """
    if max_allowed <= 0:
        return 0

    q = max_allowed // (s + 1)
    remaining = max_allowed - q * (s + 1)
    r = max(0, remaining - 1)

    return q * s + r


def get_chunk_len(max_encoded_domain_len: int, qname_encoded_len: int, max_sub_len: int, data_offset_width,
                  client_ids_width) -> int:
    max_allowed = max_encoded_domain_len - qname_encoded_len
    m = compute_max_m(max_sub_len, max_allowed)
    chunk_len = m - client_ids_width - data_offset_width - 2  # fragment_part_width is 2
    if chunk_len <= 0:
        raise ValueError("max_encoded_domain_len is too small to fit any data")
    return chunk_len


def get_base32_final_domains(data: bytes, data_offset: int, chunk_len: int, qname_encoded: bytes, max_sub_len: int,
                             chksum_pass: bytes, data_offset_width: int,
                             max_encoded_domain_len: int, client_id_bytes: bytes) -> \
        list[bytes]:
    data = b32encode_nopad_lower(data + get_crc32_bytes(data, chksum_pass))
    if (len(data) + chunk_len - 1) // chunk_len > 64:
        print("ERROR: max_domain_len is too small, packet is not sent, len:", len(data))
        return []
    final_b_domains = []
    i = 0
    c_loop = True
    s_index = 0
    len_data = len(data)
    data_offset_bytes = number_to_base32_lower(data_offset, data_offset_width)
    while c_loop:
        chunk_data = data[s_index:s_index + chunk_len]
        s_index += chunk_len
        if s_index < len_data:
            if i & 32:
                chunk_data = b"".join((client_id_bytes, data_offset_bytes, BASE32_LIST_LOWER[i & 31], b"8", chunk_data))
            else:
                chunk_data = b"".join((client_id_bytes, data_offset_bytes, BASE32_LIST_LOWER[i], b"0", chunk_data))
        else:
            if i & 32:
                chunk_data = b"".join((client_id_bytes, data_offset_bytes, BASE32_LIST_LOWER[i & 31], b"9", chunk_data))
            else:
                chunk_data = b"".join((client_id_bytes, data_offset_bytes, BASE32_LIST_LOWER[i], b"1", chunk_data))
            c_loop = False
        final_domain = insert_dots(chunk_data, max_sub_len) + qname_encoded
        if len(final_domain) > max_encoded_domain_len:
            sys.exit("Calculation Error!!!")
        final_b_domains.append(final_domain)
        i += 1

    return final_b_domains


def get_chunk_data(data: bytes, data_offset_width: int, client_id_width: int):
    if client_id_width:
        client_id = data[:client_id_width]
        fp_index = client_id_width + data_offset_width
        data_offset = base32_to_number(data[client_id_width:fp_index])
    else:
        client_id = b""
        fp_index = data_offset_width
        data_offset = base32_to_number(data[:fp_index])

    fragment_part_raw = BASE32_LOOKUP[data[fp_index]]
    if fragment_part_raw < 0:
        raise ValueError("Invalid base32 character in fragment part")

    magic = data[fp_index + 1]
    if magic == 48:  # b"0"
        fragment_part = fragment_part_raw
        last_fragment = False
    elif magic == 49:  # b"1"
        fragment_part = fragment_part_raw
        last_fragment = True
    elif magic == 56:  # b"8"
        fragment_part = fragment_part_raw | 32
        last_fragment = False
    elif magic == 57:  # b"9"
        fragment_part = fragment_part_raw | 32
        last_fragment = True
    else:
        raise ValueError("Unknown magic")

    e_data = data[fp_index + 2:]
    return client_id, data_offset, fragment_part, last_fragment, e_data
