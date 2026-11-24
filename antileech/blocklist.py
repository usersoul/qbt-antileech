"""qBittorrent「IP 过滤 → 手动屏蔽 IP 地址」列表管理。

对应 WebUI 偏好项 ``banned_IPs``（app/preferences 读写），由 qBittorrent
自己持久化，重启后依然生效，不需要写 ipfilter.dat，也不需要 reload。

两个必须注意的点：

1. ``banned_IPs`` 是**全量替换**语义。直接写入我们的列表会把用户手工添加的
   条目冲掉，所以必须：读取现有列表 → 剔除"上一次由本系统写入的条目" →
   合并本次封禁 → 写回。用户自己加的条目永远保留。
2. ``banned_IPs`` 在 WebUI API 里是**换行分隔的字符串**，不是 JSON 数组
   （qB source: ``session->bannedIPs().join('\n')`` /
   ``setBannedIPs(value.toString().split('\n'))``）。传数组会被 Qt 转成
   空字符串，等于把整个列表清空。
2. 该列表和 ipfilter 一样，主要作用于**新连接**。已经建立的连接仍由
   ``transfer/banPeers`` 负责断开，两者配合才能做到"立刻断 + 不再连"。
"""

from __future__ import annotations

import json
import logging
from typing import Iterable, List, Optional

log = logging.getLogger(__name__)

KV_KEY = "manual_banned_ips"


class ManualBanList:
    def __init__(self, qbt, store, max_entries: int = 5000, expand=None):
        self.qbt = qbt
        self.store = store
        self.max_entries = max(1, int(max_entries))
        # expand(ip) -> [ip 的多种合法写法]，用于 ::ffff:a.b.c.d 这类双栈别名
        self.expand = expand
        raw = store.kv_get(KV_KEY, "")
        try:
            self.owned = set(json.loads(raw)) if raw else set()
        except (ValueError, TypeError):
            self.owned = set()
        self.last_count = 0
        self.last_ok: Optional[bool] = None

    # ---------- 读写 ----------
    def _fetch(self) -> List[str]:
        prefs = self.qbt.preferences()
        values = prefs.get("banned_IPs") or []
        if isinstance(values, str):
            values = [v for v in values.replace(",", "\n").splitlines() if v.strip()]
        out = []
        for item in values:
            text = str(item).strip()
            if text:
                out.append(text)
        return out

    def _write(self, entries: List[str]) -> bool:
        # 必须传字符串：qB 的 setPreferences 会对该值做 toString().split('\n')，
        # 传 JSON 数组会被转成空串并清空列表。
        self.qbt.set_preferences({"banned_IPs": "\n".join(entries)})
        return True

    def sync(self, desired: Iterable[str]) -> bool:
        """把当前生效封禁同步到 qB 的手动屏蔽列表。返回是否发生写入。"""
        wanted: List[str] = []
        for item in desired:
            forms = list(self.expand(item)) if self.expand else [str(item).strip()]
            for text in forms:
                text = str(text).strip()
                if text and text not in wanted:
                    wanted.append(text)
        if len(wanted) > self.max_entries:
            log.error("手动屏蔽条目 %d 超过上限 %d，超出部分不会下发",
                      len(wanted), self.max_entries)
            wanted = wanted[: self.max_entries]

        try:
            current = self._fetch()
        except Exception as exc:  # noqa: BLE001
            log.error("读取手动屏蔽列表失败: %s", exc)
            self.last_ok = False
            return False

        # 保留用户自己添加的条目，只剔除本系统上一轮写入的
        base = [x for x in current if x not in self.owned]
        merged: List[str] = []
        for item in base + wanted:
            if item not in merged:
                merged.append(item)

        changed = (set(merged) != set(current)) or (len(merged) != len(current))
        if changed:
            try:
                self._write(merged)
            except Exception as exc:  # noqa: BLE001
                log.error("写入手动屏蔽列表失败: %s", exc)
                self.last_ok = False
                return False
            try:
                after = self._fetch()
                missing = [x for x in wanted if x not in after]
                if missing:
                    log.error("手动屏蔽列表写入后仍缺少 %d 条（示例: %s）",
                              len(missing), missing[0])
                    self.last_ok = False
                else:
                    self.last_ok = True
                self.last_count = len(after)
            except Exception:  # noqa: BLE001
                # 写入已成功，读回失败不阻塞
                self.last_ok = True
                self.last_count = len(merged)
            log.info("手动屏蔽列表已更新：%d 条（其中本系统 %d 条）",
                     self.last_count, len(wanted))
        else:
            self.last_ok = True
            self.last_count = len(current)

        self.owned = set(wanted)
        try:
            self.store.kv_set(KV_KEY, json.dumps(sorted(self.owned), ensure_ascii=False))
        except Exception:  # noqa: BLE001
            pass
        return changed

    def force_remove_all(self) -> bool:
        """清空本系统写入的条目，保留用户手工条目（卸载/切换模式时用）。"""
        try:
            current = self._fetch()
        except Exception as exc:  # noqa: BLE001
            log.error("读取手动屏蔽列表失败: %s", exc)
            return False
        remain = [x for x in current if x not in self.owned]
        if len(remain) != len(current):
            self._write(remain)
            log.info("已从手动屏蔽列表移除本系统条目 %d 条", len(current) - len(remain))
        self.owned = set()
        self.store.kv_set(KV_KEY, "")
        return True
