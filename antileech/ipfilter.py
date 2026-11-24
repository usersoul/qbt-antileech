"""qBittorrent IP 过滤器管理（持久层封禁）。

关键点：qBittorrent 没有"重新加载 IP 过滤器"的 WebUI API，只有 GUI 里的
Reload 按钮。仅把文件写盘、依赖 QFileSystemWatcher 在 Windows 上并不可靠
（尤其是原地截断写入 / 原子替换后，监视器可能丢失句柄）。

因此本模块在写盘后显式执行一次重载：
    ip_filter_enabled = false  ->  ip_filter_enabled = true + 路径
关闭再开启必然让 qB 重新解析过滤器文件，这是 API 层唯一可靠的强制重载方式
（代价是约 200ms 的无过滤窗口）。

文件格式使用 qBittorrent 兼容的 eMule 风格：
    1.2.3.4 - 1.2.3.4 , 000 , QBT-ANTILEECH
IPv6 同样写成 "v6 - v6" 范围。
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import time
from typing import List, Optional, Tuple

from .store import Store
from .util import parse_target

log = logging.getLogger(__name__)

BEGIN = "# QBT-ANTILEECH BEGIN"
END = "# QBT-ANTILEECH END"

RELOAD_MODES = ("toggle", "none")


class IpFilter:
    def __init__(self, path: str, base_file: str = "", enabled: bool = True,
                 reload_mode: str = "toggle"):
        self.path = os.path.abspath(path)
        self.base_file = os.path.abspath(base_file) if base_file else ""
        self.enabled = bool(enabled)
        mode = str(reload_mode or "toggle").lower()
        if mode not in RELOAD_MODES:
            log.warning("未知的 ip_filter.reload_mode=%s，回退为 toggle", mode)
            mode = "toggle"
        self.reload_mode = mode
        self.dirty = True

    # ---------- 构建 ----------
    def _read_base(self) -> List[str]:
        if not self.base_file or not os.path.isfile(self.base_file):
            return []
        out: List[str] = []
        try:
            with open(self.base_file, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    s = line.rstrip("\r\n")
                    if not s.strip():
                        continue
                    if s.strip().startswith(("#", "//")):
                        continue
                    out.append(s)
        except OSError as exc:
            log.warning("读取基础名单失败 %s: %s", self.base_file, exc)
        return out

    def build(self, ban_ips: List[str]) -> str:
        ranges: List[Tuple[int, int, int]] = []
        for ip in ban_ips:
            parsed = parse_target(ip)
            if parsed and parsed[2] in (4, 6):
                ranges.append(parsed)

        # 排序 + 合并相邻/重叠区间，减少行数
        ranges.sort(key=lambda x: (x[2], x[0], x[1]))
        merged: List[List[int]] = []
        for start, end, ver in ranges:
            if merged and merged[-1][2] == ver and start <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end, ver])

        lines: List[str] = [
            "# qBittorrent AntiLeech - auto generated, do not edit",
            "# 由 antileech 写入；修改请改配置或数据库",
        ]
        base_lines = self._read_base()
        if base_lines:
            lines.append("# ---- base blocklist (merged) ----")
            lines.extend(base_lines)
        lines.append(BEGIN)
        for start, end, ver in merged:
            cls = ipaddress.IPv4Address if ver == 4 else ipaddress.IPv6Address
            lines.append("%s - %s , 000 , QBT-ANTILEECH" % (cls(start), cls(end)))
        lines.append(END)
        lines.append("")
        return "\n".join(lines)

    # ---------- 落盘 ----------
    def _write(self, content: str) -> bool:
        """先写临时文件再原子替换；被 qB 短暂占用时重试，最后退回原地写。"""
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            log.error("写入临时过滤器失败 %s: %s", tmp, exc)
            return False

        for _ in range(5):
            try:
                os.replace(tmp, self.path)
                return True
            except OSError:
                time.sleep(0.2)

        # 原子替换失败（常见于 qB 正持有文件句柄），退回原地写入
        try:
            with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            return True
        except OSError as exc:
            log.error("写入 IP 过滤器失败 %s: %s", self.path, exc)
            return False
        finally:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass

    def sync(self, ban_ips: List[str]) -> bool:
        """写文件；内容无变化则跳过。返回是否发生写入。"""
        if not self.enabled:
            return False
        content = self.build(ban_ips)
        digest = hashlib.sha1(content.encode("utf-8")).hexdigest()
        try:
            if os.path.isfile(self.path):
                with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                    if hashlib.sha1(fh.read().encode("utf-8")).hexdigest() == digest:
                        return False
        except OSError:
            pass
        if not self._write(content):
            return False
        log.info("IP 过滤器已写入: %s（%d 条封禁）", self.path, len(ban_ips))
        return True

    # ---------- 与 qB 交互 ----------
    def _normalized(self, value: str) -> str:
        text = str(value or "")
        return os.path.normcase(os.path.normpath(text)) if text else ""

    def prefs_ok(self, qbt) -> bool:
        """只读检查：qB 是否已启用过滤器且路径指向本文件。"""
        if not self.enabled:
            return True
        try:
            prefs = qbt.preferences()
        except Exception as exc:  # noqa: BLE001
            log.warning("读取 qBittorrent 偏好失败: %s", exc)
            return False
        return bool(prefs.get("ip_filter_enabled")) and \
            self._normalized(prefs.get("ip_filter_path")) == self._normalized(self.path)

    def reload(self, qbt, force: bool = False) -> bool:
        """让 qBittorrent 真正重新加载过滤器文件。

        toggle: 关闭 -> 开启（默认，唯一可靠的 API 级强制重载）
        none:   仅设置路径，依赖 qB 自身的文件监视器
        """
        if not self.enabled:
            return True
        if self.reload_mode == "none" and not force:
            try:
                qbt.set_preferences({
                    "ip_filter_enabled": True,
                    "ip_filter_path": self.path,
                })
                return True
            except Exception as exc:  # noqa: BLE001
                log.error("设置 IP 过滤器失败: %s", exc)
                return False

        try:
            # 1) 关闭过滤：确保 qB 丢弃旧规则
            qbt.set_preferences({"ip_filter_enabled": False})
            time.sleep(0.2)
            # 2) 重新开启并指定路径：qB 必须重新解析文件
            qbt.set_preferences({
                "ip_filter_enabled": True,
                "ip_filter_path": self.path,
            })
            time.sleep(0.2)
        except Exception as exc:  # noqa: BLE001
            log.error("重载 IP 过滤器失败: %s", exc)
            return False

        if self.prefs_ok(qbt):
            log.info("IP 过滤器已重载: %s", self.path)
            return True

        # 再试一次，仍然失败则明确报错（此时仍可依赖 banPeers 兜底）
        try:
            qbt.set_preferences({"ip_filter_enabled": False})
            time.sleep(0.3)
            qbt.set_preferences({"ip_filter_enabled": True, "ip_filter_path": self.path})
            time.sleep(0.3)
        except Exception as exc:  # noqa: BLE001
            log.error("重载 IP 过滤器重试失败: %s", exc)
            return False
        ok = self.prefs_ok(qbt)
        if not ok:
            log.error("IP 过滤器重载后参数仍不正确，请检查 WebUI 权限或手动点一次 Reload")
        return ok

    def ensure_registered(self, qbt) -> bool:
        """兼容旧调用：确保路径已注册，必要时强制重载。返回是否成功。"""
        if not self.enabled:
            return True
        if self.prefs_ok(qbt):
            return True
        return self.reload(qbt, force=True)