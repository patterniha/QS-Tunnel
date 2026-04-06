import base64

BASE32_LIST_UPPER = [b"A", b"B", b"C", b"D", b"E", b"F", b"G", b"H", b"I", b"J", b"K", b"L", b"M", b"N", b"O", b"P",
                     b"Q", b"R", b"S", b"T", b"U", b"V", b"W", b"X", b"Y", b"Z", b"2", b"3", b"4", b"5", b"6", b"7"]

BASE32_LIST_LOWER = [b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h", b"i", b"j", b"k", b"l", b"m", b"n", b"o", b"p",
                     b"q", b"r", b"s", b"t", b"u", b"v", b"w", b"x", b"y", b"z", b"2", b"3", b"4", b"5", b"6", b"7"]

BASE32_CHARS_BYTES_UPPER = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
BASE32_CHARS_BYTES_LOWER = b"abcdefghijklmnopqrstuvwxyz234567"

BASE32_LOOKUP = [-1] * 256
for i, ch in enumerate(BASE32_CHARS_BYTES_UPPER):
    BASE32_LOOKUP[ch] = i
    lower_ch = BASE32_CHARS_BYTES_LOWER[i]
    if lower_ch != ch:
        BASE32_LOOKUP[lower_ch] = i


def number_to_base32_lower(n: int, width: int) -> bytes:
    result = [b""] * width
    for i in range(width - 1, -1, -1):
        remainder, n = n & 31, n >> 5
        result[i] = BASE32_LIST_LOWER[remainder]
    return b"".join(result)


def base32_to_number(s: bytes) -> int:
    value = 0
    for ch in s:
        idx = BASE32_LOOKUP[ch]
        if idx < 0:
            raise ValueError(f"Invalid base32 character: {ch}")
        value = (value << 5) + idx
    return value


def b32decode_nopad(s: bytes) -> bytes:
    pad = (-len(s)) & 7
    return base64.b32decode(s + b"=" * pad, casefold=True)


def b32encode_nopad_lower(s: bytes) -> bytes:
    return base64.b32encode(s).rstrip(b"=").lower()
