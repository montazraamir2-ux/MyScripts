from __future__ import annotations

import array
import fcntl
import json
import socket
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network

_SIOCGIFCONF = 0x8912
_SIOCGIFNETMASK = 0x891B
_IFREQ_SIZE = 40
_IFREQ_BUF_LEN = 4096


@dataclass
class NetworkInfo:
    local_ip: str
    network_address: str
    broadcast_address: str
    prefix_length: int
    total_hosts: int
    usable_hosts: int
    cidr_notation: str
    active_interface: str


def get_local_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]


def _enumerate_iface_ips() -> list[tuple[str, str]]:
    buf = array.array("B", b"\x00" * _IFREQ_BUF_LEN)
    buf_addr = buf.buffer_info()[0]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        raw = fcntl.ioctl(s.fileno(), _SIOCGIFCONF, struct.pack("iL", _IFREQ_BUF_LEN, buf_addr))
    nbytes = struct.unpack("iL", raw)[0]
    data = bytes(buf[:nbytes])
    pairs: list[tuple[str, str]] = []
    offset = 0
    while offset + _IFREQ_SIZE <= nbytes:
        name = data[offset:offset + 16].rstrip(b"\x00").decode().strip()
        family = struct.unpack_from("H", data, offset + 16)[0]
        if family == socket.AF_INET:
            ip = socket.inet_ntoa(data[offset + 20:offset + 24])
            pairs.append((name, ip))
        offset += _IFREQ_SIZE
    return pairs


def get_active_interface(local_ip: str) -> str:
    for iface, ip in _enumerate_iface_ips():
        if ip == local_ip:
            return iface
    return "unknown"


def _iface_netmask(ifname: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        buf = struct.pack("256s", ifname[:15].encode())
        result = fcntl.ioctl(s.fileno(), _SIOCGIFNETMASK, buf)
    return socket.inet_ntoa(result[20:24])


def get_real_prefix(local_ip: str) -> int:
    iface = get_active_interface(local_ip)
    if iface == "unknown":
        return 24
    try:
        netmask = _iface_netmask(iface)
        return IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    except OSError as _:
        return 24


def get_network_info() -> NetworkInfo:
    local_ip = get_local_ip()
    prefix = get_real_prefix(local_ip)
    iface = get_active_interface(local_ip)
    network = IPv4Network(f"{local_ip}/{prefix}", strict=False)
    return NetworkInfo(
        local_ip=local_ip,
        network_address=str(network.network_address),
        broadcast_address=str(network.broadcast_address),
        prefix_length=prefix,
        total_hosts=network.num_addresses,
        usable_hosts=len(list(network.hosts())),
        cidr_notation=str(network),
        active_interface=iface,
    )


def iter_usable_hosts(network_info: NetworkInfo) -> Iterator[IPv4Address]:
    network = IPv4Network(f"{network_info.network_address}/{network_info.prefix_length}")
    yield from network.hosts()


def iter_cidr_hosts(cidr: str) -> Iterator[IPv4Address]:
    yield from IPv4Network(cidr, strict=False).hosts()


def to_log_dict(network_info: NetworkInfo) -> dict:
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "tool": "network_info",
        "local_ip": network_info.local_ip,
        "cidr": network_info.cidr_notation,
        "interface": network_info.active_interface,
        "prefix_length": network_info.prefix_length,
        "usable_hosts": network_info.usable_hosts,
    }
