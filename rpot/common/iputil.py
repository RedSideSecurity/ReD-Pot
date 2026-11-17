"""IP address helpers shared by decoys and the manager.

A dual-stack socket reports IPv4 peers as IPv4-mapped IPv6 (``::ffff:192.168.1.10``). Every place that
classifies an address (internal / allow-listed / private / GeoIP) or stores it must see the plain IPv4
form, otherwise an internal host looks external and IPv4 allow-lists never match.
"""
import ipaddress


def ip_obj(ip):
    """`ip` as an ipaddress object with IPv4-mapped IPv6 unwrapped to IPv4; None if it is not an address."""
    if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        a = ip
    else:
        try:
            a = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return None
    if a.version == 6 and a.ipv4_mapped:
        return a.ipv4_mapped
    return a


def norm_ip(ip):
    """Normalised text form of an address (mapped IPv6 → IPv4); anything that is not an address is
    returned unchanged (callers keep their own validation)."""
    if ip is None:
        return None
    a = ip_obj(ip)
    return str(a) if a is not None else ip
