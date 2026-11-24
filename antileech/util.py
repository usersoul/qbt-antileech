"""通用工具：IP 归一化、白名单匹配、封禁键生成。"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Optional, Tuple

_SPECIAL = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)

DEFAULT_PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in _SPECIAL)


def normalize_ip(raw) -> Optional[ipaddress._BaseAddress]:
    """把 WebUI 返回的 IP 文本转成 ip_address 对象，非法返回 None。"""
    if raw is None:
        return None
    text = str(raw).strip().strip("[]")
    if not text:
        return None
    if "%" in text:  # 去掉 IPv6 zone id，例如 fe80::1%12
        text = text.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr


def parse_networks(items: Iterable[str]) -> Tuple[ipaddress._BaseNetwork, ...]:
    nets = []
    for item in items or []:
        try:
            nets.append(ipaddress.ip_network(str(item).strip(), strict=False))
        except ValueError:
            continue
    return tuple(nets)


def is_private(addr) -> bool:
    for net in DEFAULT_PRIVATE_NETS:
        if addr.version == net.version and addr in net:
            return True
    return False


def in_networks(addr, nets) -> bool:
    for net in nets:
        if addr.version == net.version and addr in net:
            return True
    return False


def coerce_ip(raw):
    """尽量把 WebUI 报的 IP 文本转成 ip_address；失败返回 None。

    qBittorrent 在双栈 socket 下会把 IPv4 报成 "::ffff:a.b.c.d"，
    个别写法 ipaddress 解析不出来，这里先剥 ::ffff: 前缀重试一次。
    """
    text = str(raw or "").strip().strip("[]")
    if not text:
        return None
    addr = normalize_ip(text)
    if addr is not None:
        return addr
    lowered = text.lower()
    for prefix in ("::ffff:", "0:0:0:0:0:ffff:"):
        if lowered.startswith(prefix):
            tail = normalize_ip(text[len(prefix):])
            # 只有尾巴本身是点分 IPv4 才认定是 IPv4-mapped 写法；
            # 否则属于畸形字符串，宁可当成无法解析，不要猜测成另一个主机
            if tail is not None and tail.version == 4:
                return tail
            return None
    return None


def ban_forms(normalized: str, raw: str = "") -> list:
    """返回下发给 qBittorrent 的全部地址写法。

    qB 的 banPeers 按 ip:port 字面量匹配当前连接，banned_IPs 也按字符串存储；
    只发归一化后的 58.219.53.198，可能匹配不到它记录的 ::ffff:58.219.53.198，
    于是"已封禁"却不断连。两种写法一起发最稳。
    """
    forms = []
    for value in (normalized, raw):
        text = str(value or "").strip()
        if text and text not in forms:
            forms.append(text)
    try:
        import ipaddress
        addr = ipaddress.ip_address(normalized)
        if addr.version == 4:
            mapped = "::ffff:%s" % addr
            if mapped not in forms:
                forms.append(mapped)
    except ValueError:
        pass
    return forms


def format_ban_peer(ip: str, port: int) -> str:
    """qBittorrent 的 transfer/banPeers 需要 "ip:port"。
    IPv6 直接写裸地址，qB 按最后一个冒号切分端口。"""
    return "%s:%d" % (ip, int(port or 0))


def ban_key(ip: str, v6_prefix: int = 0) -> str:
    """生成封禁键。v6_prefix>0 时把 IPv6 收敛到网段（默认关闭，避免误伤）。"""
    addr = normalize_ip(ip)
    if addr is None:
        return ip
    if addr.version == 6 and v6_prefix and v6_prefix < 128:
        return str(ipaddress.ip_network("%s/%d" % (addr, v6_prefix), strict=False))
    return str(addr)


def parse_target(text: str):
    """把 "1.2.3.4" 或 "1.2.3.0/24" 解析为 (start_int, end_int, version)。"""
    s = str(text).strip()
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        addr = normalize_ip(s)
        if addr is None:
            return None
        return int(addr), int(addr), addr.version
    return int(net.network_address), int(net.broadcast_address), net.version


def human_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024.0 or unit == "TiB":
            return "%.2f%s" % (n, unit)
        n /= 1024.0
    return "%.2fTiB" % n
