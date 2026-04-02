from struct import pack, unpack_from


def label_domain(domain: bytes) -> list[bytes]:
    return [label for label in domain.strip(b".").split(b".") if label]


def encode_qname(domain: bytes) -> bytes:
    result = []
    for label in domain.strip(b".").split(b"."):
        if label:
            result.append(bytes((len(label),)))
            result.append(label)

    return b"".join(result) + b"\x00"


def build_dns_query(qname_encoded: bytes, q_id: int, qtype: int) -> bytes:
    """
    qname_encoded: bytes with DNS label encoding (length-prefixed labels) ending with b'\\x00'
    q_id: 16-bit query ID
    qtype: 16-bit QTYPE (e.g., 1=A, 28=AAAA)
    """
    if not qname_encoded or qname_encoded[-1] != 0:
        raise ValueError("qname_encoded must end with a null byte (\\x00)")

    header = pack(
        "!HHHHHH",
        q_id & 0xFFFF,  # ID
        0x0100,  # flags: recursion desired
        1,  # QDCOUNT
        0,  # ANCOUNT
        0,  # NSCOUNT
        0,  # ARCOUNT
    )

    question = qname_encoded + pack("!HH", qtype & 0xFFFF, 0x0001)
    return header + question


def insert_dots(data: bytes, max_sub: int = 63) -> bytes:
    n = len(data)
    # chunks = (n + max_sub - 1) // max_sub
    out = []
    for i in range(0, n, max_sub):
        seg = data[i:i + max_sub]
        out.append(bytes((len(seg),)))
        out.append(seg)

    return b"".join(out)


def handle_question(data: bytes, offset: int) -> tuple[list, int, int]:
    labels = []
    len_data = len(data)
    while offset < len_data:
        label_len = data[offset]
        if label_len == 0:
            qtype, qclass = unpack_from("!HH", data, offset + 1)
            if qclass != 1:
                raise ValueError
            next_question = offset + 5
            if next_question > len_data:
                raise ValueError
            return labels, qtype, next_question
        if label_len > 63:
            raise ValueError
        lable_s = offset + 1
        offset = lable_s + label_len
        labels.append(data[lable_s:offset].lower())
    raise ValueError


def handle_dns_request(data: bytes) -> tuple[int, int, list, int, int]:
    if len(data) < 17:
        raise ValueError

    qid, qflags, qdcount = unpack_from("!HHH", data, 0)
    if qdcount != 1:
        raise ValueError("not 1 question")
    if qflags & 0x8000:
        raise ValueError("not query")
    labels, qtype, next_question = handle_question(data, 12)

    return qid, qflags, labels, qtype, next_question  # question = data[12:next_question]


def create_noerror_empty_response(qid: int, qflags: int, question: bytes) -> bytes:
    # QR = 1
    # Opcode = echo
    # AA = 1
    # TC = 0
    # RD = echo
    # RA = 0
    # Z  = 0
    # AD = 0
    # CD = echo
    # RCODE = 0 if opcode==0 else 4

    rflags = 0x8400 | (qflags & 0x7910) | (((qflags & 0x7800) != 0) << 2)

    header = pack("!HHHHHH", qid, rflags, 1, 0, 0, 0)

    return header + question
