"""可选的 Windows 防火墙硬封禁（默认关闭）。

说明：防火墙规则是最"硬"的一层，但会同时阻断该 IP 的所有流量，
若对方是共享出口 IP（NAT/机房）可能误伤他人。默认关闭，需显式开启。
"""

from __future__ import annotations

import logging
import platform
import subprocess

log = logging.getLogger(__name__)


class Firewall:
    def __init__(self, enabled: bool = False, prefix: str = "QBT-AntiLeech",
                 group: str = "qBittorrent AntiLeech"):
        self.requested = bool(enabled)
        self.is_windows = platform.system().lower() == "windows"
        self.enabled = self.requested and self.is_windows
        self.prefix = prefix
        self.group = group
        if self.requested and not self.is_windows:
            log.warning("防火墙封禁仅在 Windows 生效，当前系统已忽略")

    def _rule_name(self, ip: str) -> str:
        return "%s-%s" % (self.prefix, ip.replace(":", "_"))

    def _run(self, args):
        try:
            proc = subprocess.run(
                ["netsh", "advfirewall", "firewall"] + args,
                capture_output=True, text=True, timeout=25
            )
            return proc.returncode == 0, (proc.stdout or "") + (proc.stderr or "")
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    def block(self, ip: str) -> bool:
        if not self.enabled:
            return False
        name = self._rule_name(ip)
        ok1, out1 = self._run(["add", "rule", "name=%s" % name, "dir=in",
                               "action=block", "remoteip=%s" % ip,
                               "group=%s" % self.group, "enable=yes"])
        ok2, out2 = self._run(["add", "rule", "name=%s-out" % name, "dir=out",
                               "action=block", "remoteip=%s" % ip,
                               "group=%s" % self.group, "enable=yes"])
        if not (ok1 and ok2):
            log.warning("防火墙封禁失败 %s: %s %s", ip, out1.strip(), out2.strip())
        return ok1 and ok2

    def unblock(self, ip: str) -> bool:
        if not self.enabled:
            return False
        name = self._rule_name(ip)
        ok1, _ = self._run(["delete", "rule", "name=%s" % name])
        ok2, _ = self._run(["delete", "rule", "name=%s-out" % name])
        return ok1 or ok2
