"""Minimal ASN.1 BER/DER codec for the LDAP and Kerberos decoys (stdlib only).

A decoded element is a tuple (tag_byte, value) where value is bytes for primitives and a list
of elements for constructed types. Strict bounds checks: malformed input raises ValueError,
never reads past the buffer, and nesting depth is capped (hostile input).
"""

MAX_DEPTH = 32


def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + _len(len(content)) + content


def seq(*items, tag=0x30):
    return tlv(tag, b"".join(items))


def integer(n, tag=0x02):
    if n == 0:
        return tlv(tag, b"\x00")
    b = n.to_bytes((n.bit_length() + 8) // 8, "big", signed=True)
    return tlv(tag, b)


def enum(n):
    return integer(n, tag=0x0A)


def octets(s, tag=0x04):
    return tlv(tag, s if isinstance(s, bytes) else str(s).encode("utf-8"))


def gstring(s):                        # Kerberos GeneralString
    return octets(s, tag=0x1B)


def ctx(n, content, constructed=True):
    return tlv((0xA0 if constructed else 0x80) | n, content)


def app(n, content, constructed=True):
    return tlv((0x60 if constructed else 0x40) | n, content)


def read_tlv(buf, pos=0):
    """→ (tag, content_bytes, next_pos)"""
    if pos + 2 > len(buf):
        raise ValueError("truncated header")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise ValueError("high tag numbers not supported")
    n = buf[pos + 1]
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or pos + k > len(buf):
            raise ValueError("bad length")
        n = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    if pos + n > len(buf):
        raise ValueError("truncated value")
    return tag, buf[pos:pos + n], pos + n


def decode(buf, depth=0):
    """Decode ALL elements in buf → list of (tag, value)."""
    if depth > MAX_DEPTH:
        raise ValueError("too deep")
    out, pos = [], 0
    while pos < len(buf):
        tag, content, pos = read_tlv(buf, pos)
        out.append((tag, decode(content, depth + 1) if tag & 0x20 else content))
    return out


def one(buf):
    els = decode(buf)
    if not els:
        raise ValueError("empty")
    return els[0]


def as_int(v):
    return int.from_bytes(v, "big", signed=True) if v else 0


def as_str(v):
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else ""


def find(els, tag):
    """First child with this tag in a constructed value, or None."""
    for t, v in els if isinstance(els, list) else []:
        if t == tag:
            return v
    return None


def walk_strings(v, out=None, depth=0):
    """All primitive byte strings below v (for loose filter inspection)."""
    out = [] if out is None else out
    if depth > MAX_DEPTH:
        return out
    if isinstance(v, list):
        for _, x in v:
            walk_strings(x, out, depth + 1)
    elif isinstance(v, (bytes, bytearray)):
        out.append(bytes(v))
    return out


def win(buf, depth=0):
    """Re-encode like Windows' LDAP server: every constructed element with a 4-byte (0x84) length, primitives
    minimal — the byte pattern nmap's "Microsoft Windows Active Directory LDAP" signature matches."""
    if depth > MAX_DEPTH:
        raise ValueError("too deep")
    out, pos = [], 0
    while pos < len(buf):
        tag, content, pos = read_tlv(buf, pos)
        if tag & 0x20:
            inner = win(content, depth + 1)
            out.append(bytes([tag, 0x84]) + len(inner).to_bytes(4, "big") + inner)
        else:
            out.append(bytes([tag]) + _len(len(content)) + content)
    return b"".join(out)
