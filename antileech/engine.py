"""主引擎：采集 Peer → 评分 → 封禁 → 持久化 → 自动恢复。"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Dict, List, Tuple

from .config import Config
from .firewall import Firewall
from .blocklist import ManualBanList
from .ipfilter import IpFilter
from .qbt import QbtAuthError, QbtClient, QbtError
from .rules import Sample, evaluate
from .store import Store
from .util import (ban_forms, coerce_ip, format_ban_peer, in_networks, is_private,
                    normalize_ip, parse_networks)

log = logging.getLogger(__name__)


class Engine:
    def __init__(self, cfg: Config, dry_run=None):
        self.cfg = cfg
        self.dry_run = bool(cfg.get("ban.dry_run", False)) if dry_run is None else bool(dry_run)

        q = cfg.section("qbt")
        self.qbt = QbtClient(
            base_url=q.get("base_url", "http://127.0.0.1:8080"),
            username=q.get("username", "admin"),
            password=q.get("password", ""),
            timeout=q.get("timeout", 15),
            verify=q.get("verify_tls", True),
            max_retries=q.get("max_retries", 3),
            trust_env=q.get("trust_env_proxy", False),
            api_key=q.get("api_key", ""),
        )
        self.store = Store(cfg.db_path)
        self.filter = IpFilter(
            path=cfg.get("ip_filter.path"),
            base_file=cfg.get("ip_filter.base_file", ""),
            enabled=cfg.get("ip_filter.enabled", True),
            reload_mode=cfg.get("ip_filter.reload_mode", "toggle"),
        )
        self.blocklist_mode = str(cfg.get("blocklist.mode", "manual")).lower()
        if self.blocklist_mode not in ("manual", "file", "both"):
            self.blocklist_mode = "manual"
        self.use_file = self.blocklist_mode in ("file", "both")
        self.manual = (ManualBanList(self.qbt, self.store,
                                     cfg.get("blocklist.max_entries", 5000),
                                     expand=self._expand_forms)
                       if self.blocklist_mode in ("manual", "both") else None)

        self.fw = Firewall(
            enabled=cfg.get("firewall.enabled", False),
            prefix=cfg.get("firewall.rule_prefix", "QBT-AntiLeech"),
            group=cfg.get("firewall.group", "qBittorrent AntiLeech"),
        )
        self.allow_private = bool(cfg.get("whitelist.allow_private", True))
        self.wl_nets = parse_networks(cfg.get("whitelist.cidrs", []))
        self.wl_ips = set()
        for item in cfg.get("whitelist.ips", []) or []:
            addr = normalize_ip(item)
            if addr is not None:
                self.wl_ips.add(str(addr))

        self.ban_cache = self.store.active_ban_ips()
        self._last_filter_sync = 0.0
        self._last_housekeep = 0.0
        self._reban_ts: Dict[str, float] = {}
        self._live_eps: Dict[str, List[str]] = {}
        self._unparsed: set = set()
        self._filter_initialized = False
        self._last_reload_ok = None
        self._last_reload_ts = 0.0
        self._blocklist_dirty = True
        self._last_blocklist_sync = 0.0
        self._legacy_cleaned = False
        self.stats = {
            "started": time.time(), "cycles": 0, "peers_seen": 0,
            "bans_total": 0, "last_cycle": 0, "last_error": "",
        }

    # ---------------- 地址别名 ----------------
    def _remember_alias(self, ip_text: str, raw_text: str):
        """记住 qB 实际使用的地址写法（如 ::ffff:58.219.53.198）。"""
        if not raw_text or raw_text == ip_text:
            return
        key = "alias:" + ip_text
        try:
            cur = self.store.kv_get(key, "")
            forms = json.loads(cur) if cur else []
            if raw_text not in forms:
                forms.append(raw_text)
                self.store.kv_set(key, json.dumps(forms[-8:], ensure_ascii=False))
        except Exception as exc:  # noqa: BLE001
            log.debug("记录地址别名失败: %s", exc)

    def _expand_forms(self, ip_text: str) -> List[str]:
        """封禁下发用的全部写法：归一化 IP + ::ffff: 形式 + 历史别名。"""
        forms = ban_forms(ip_text, "")
        try:
            cur = self.store.kv_get("alias:" + ip_text, "")
            for extra in (json.loads(cur) if cur else []):
                if extra and extra not in forms:
                    forms.append(extra)
        except Exception:  # noqa: BLE001
            pass
        return forms

    # ---------------- 白名单 ----------------
    def is_whitelisted(self, addr, ip_text: str, raw_text: str = "") -> bool:
        if raw_text and raw_text in self.wl_ips:
            return True
        if ip_text in self.wl_ips:
            return True
        if addr is None:
            return False
        if in_networks(addr, self.wl_nets):
            return True
        if self.allow_private and is_private(addr):
            return True
        return False

    # ---------------- 主循环 ----------------
    def run_forever(self, once: bool = False):
        interval = float(self.cfg.get("runtime.interval_seconds", 15))
        backoff = interval
        while True:
            started = time.time()
            try:
                self.cycle()
                backoff = interval
                self.stats["last_error"] = ""
            except QbtAuthError as exc:
                self.stats["last_error"] = "auth: %s" % exc
                log.error("WebUI 认证失败（检查地址/账号/白名单）: %s", exc)
                backoff = min(max(backoff * 2, 10), 300)
            except QbtError as exc:
                self.stats["last_error"] = "qbt: %s" % exc
                log.error("qBittorrent 通信异常，稍后重试: %s", exc)
                backoff = min(max(backoff * 2, 10), 300)
            except Exception as exc:  # noqa: BLE001
                self.stats["last_error"] = "internal: %s" % exc
                log.exception("周期执行异常")
                backoff = min(max(backoff * 2, 10), 300)

            if once:
                return
            time.sleep(max(1.0, backoff - (time.time() - started)))

    def cycle(self):
        t0 = time.time()
        if not self.qbt.version:
            self.qbt.app_version()
            log.info("已连接 qBittorrent %s", self.qbt.version)

        maindata = self.qbt.maindata()
        torrents = maindata.get("torrents") or {}
        samples, truncated = self.collect(torrents)
        banned = self.process(samples)
        lifted = self.expire_bans()
        self.ensure_blocklist()
        self.housekeeping(torrents, samples)

        self.stats["cycles"] += 1
        self.stats["peers_seen"] = len(samples)
        self.stats["last_cycle"] = time.time()
        self.stats["bans_total"] = self.store.count_active_bans()
        self.write_status(torrents, truncated, banned, lifted)
        log.info("周期完成：种子%d 活跃Peer%d 新增封禁%d 解除%d 耗时%.2fs",
                 len(torrents), len(samples), len(banned), len(lifted), time.time() - t0)

    # ---------------- 采集 ----------------
    def collect(self, torrents: Dict) -> Tuple[List[Sample], int]:
        limit = int(self.cfg.get("runtime.max_torrents_per_cycle", 40))
        items = sorted(torrents.items(),
                       key=lambda kv: (kv[1].get("up_speed") or 0), reverse=True)
        truncated = max(0, len(items) - limit)
        items = items[:limit]

        samples: List[Sample] = []
        now = time.time()
        for infohash, tdata in items:
            try:
                peers = self.qbt.torrent_peers(infohash)
            except QbtError as exc:
                log.debug("读取种子 %s 的 Peer 失败: %s", infohash[:12], exc)
                continue
            for key, p in (peers or {}).items():
                raw_text = str(p.get("ip") or str(key).rsplit(":", 1)[0]).strip()
                addr = coerce_ip(raw_text)
                if addr is None:
                    # 解析不出来的地址不参与封禁（避免把垃圾字符串写进 qB 名单），
                    # 但会计数并在 status 里暴露，方便发现新的地址格式
                    if raw_text and len(self._unparsed) < 500:
                        self._unparsed.add(raw_text)
                    continue
                ip_text = str(addr)
                self._remember_alias(ip_text, raw_text)
                if self.is_whitelisted(addr, ip_text, raw_text):
                    continue
                samples.append(Sample(
                    ip=ip_text,
                    raw_ip=raw_text,
                    port=int(p.get("port") or 0),
                    infohash=infohash,
                    client=str(p.get("client") or ""),
                    peer_id=str(p.get("peer_id_client") or ""),
                    progress=float(p.get("progress") or 0.0),
                    downloaded=int(p.get("downloaded") or 0),
                    uploaded=int(p.get("uploaded") or 0),
                    dl_speed=int(p.get("dl_speed") or 0),
                    up_speed=int(p.get("up_speed") or 0),
                    connection=str(p.get("connection") or ""),
                    flags=str(p.get("flags") or ""),
                    ts=now,
                ))
        return samples, truncated

    # ---------------- 评分与封禁 ----------------
    def process(self, samples: List[Sample]) -> List[str]:
        now = time.time()
        det = self.cfg.section("detection")
        threshold = float(det.get("ban_threshold", 60))
        cap = float(det.get("score_cap", 200))

        agg: Dict[str, Dict] = {}
        for s in samples:
            prev = self.store.get_peer(s.ip, s.infohash)
            pid_count = 0
            if s.peer_id:
                pid_count = self.store.peer_id_ip_count(s.peer_id, now - 86400)
            result = evaluate(self.cfg.data, s, prev, now, pid_count)
            state = result.state
            if state is None:
                continue
            self.store.save_peer(state)
            if s.peer_id:
                self.store.bump_peer_id(s.peer_id, s.ip, now)

            item = agg.setdefault(s.ip, {
                "score": 0.0, "reasons": [], "hard": False,
                "endpoints": [], "torrents": 0, "uploaded": 0, "client": s.client,
            })
            item["torrents"] += 1
            item["uploaded"] += s.uploaded
            item["score"] = max(item["score"], state.score)
            item["hard"] = item["hard"] or result.hard
            item["reasons"].extend(result.reasons)
            if s.port:
                for form in ban_forms(s.ip, s.raw_ip):
                    ep = format_ban_peer(form, s.port)
                    if ep not in item["endpoints"]:
                        item["endpoints"].append(ep)

        newly: List[str] = []
        for ip, item in agg.items():
            total = min(cap, item["score"] + 5.0 * max(0, item["torrents"] - 1))
            if ip in self.ban_cache:
                self.reban(ip, item["endpoints"])
                continue
            if item["hard"] or total >= threshold:
                if self.ban(ip, total, item["reasons"], item["hard"], item["endpoints"]):
                    newly.append(ip)
        # 记录本周期仍在线的封禁对象端点，供过滤器重载后立即补发 banPeers
        self._live_eps = {ip: item["endpoints"] for ip, item in agg.items() if item["endpoints"]}
        return newly

    def _mark_blocklist_dirty(self):
        self._blocklist_dirty = True
        if self.use_file:
            self.filter.dirty = True

    def ban(self, ip: str, score: float, reasons: List[str], hard: bool,
            endpoints: List[str]) -> bool:
        max_bans = int(self.cfg.get("ban.max_bans", 50000))
        if len(self.ban_cache) >= max_bans:
            log.error("封禁列表已达上限 %d，跳过 %s", max_bans, ip)
            return False
        duration = (int(self.cfg.get("ban.hard_duration_seconds", 604800)) if hard
                    else int(self.cfg.get("ban.duration_seconds", 86400)))
        reason = "; ".join(dict.fromkeys(reasons))[:400] or "manual"
        expires = (time.time() + duration) if duration > 0 else 0.0

        self.store.add_ban(ip, reason, score, time.time(), expires, "auto")
        self.store.record_event(ip, "ban", reason, "score=%.1f hard=%s" % (score, hard))
        self.ban_cache.add(ip)
        self._mark_blocklist_dirty()
        log.warning("[封禁] %s 分数=%.1f 时长=%ss 原因=%s", ip, score, duration, reason)

        if self.dry_run:
            log.info("[DRY-RUN] 未实际下发封禁: %s", ip)
            return True
        if endpoints:
            try:
                self.qbt.ban_peers(endpoints[:50])
            except QbtError as exc:
                log.error("banPeers 下发失败 %s: %s", ip, exc)
        if self.fw.enabled:
            self.fw.block(ip)
        return True

    def reban(self, ip: str, endpoints: List[str]):
        """qBittorrent 重启后会话级封禁会丢失，对仍然连上的黑名单 IP 自动补发。"""
        if self.dry_run or not endpoints:
            return
        now = time.time()
        if now - self._reban_ts.get(ip, 0) < 600:
            return
        try:
            self.qbt.ban_peers(endpoints[:20])
            self._reban_ts[ip] = now
            log.debug("已补发封禁 %s", ip)
        except QbtError:
            pass

    def reban_all_active(self) -> int:
        """过滤器重载后，对本周期仍在线且已封禁的 IP 立即补发 banPeers。

        重载会短暂关闭过滤器，且 libtorrent 的 ip_filter 主要作用于新连接，
        已建立的连接需要 banPeers 才能立刻断开。
        """
        if self.dry_run:
            return 0
        sent = 0
        now = time.time()
        for ip, eps in list(self._live_eps.items()):
            if ip not in self.ban_cache or not eps:
                continue
            if now - self._reban_ts.get(ip, 0) < 300:
                continue
            try:
                self.qbt.ban_peers(eps[:20])
                self._reban_ts[ip] = now
                sent += min(len(eps), 20)
            except QbtError as exc:
                log.debug("补发封禁失败 %s: %s", ip, exc)
        if sent:
            log.info("过滤器重载后补发 banPeers：%d 个连接", sent)
        return sent

    def expire_bans(self) -> List[str]:
        lifted = []
        for ban in self.store.expired_bans(time.time()):
            self.store.deactivate_ban(ban.ip)
            self.store.record_event(ban.ip, "unban", "自动解除(到期)", ban.reason)
            self.ban_cache.discard(ban.ip)
            self._mark_blocklist_dirty()
            if self.fw.enabled:
                self.fw.unblock(ban.ip)
            lifted.append(ban.ip)
            log.info("[自动解除] %s（原原因: %s）", ban.ip, ban.reason[:80])
        return lifted

    # ---------------- 封禁名单同步 ----------------
    def ensure_blocklist(self, force: bool = False):
        """把手动屏蔽列表（banned_IPs）与可选的文件过滤器同步给 qB。"""
        if self.manual is None and not self.use_file:
            return
        now = time.time()
        interval = float(self.cfg.get("blocklist.sync_interval_seconds", 60))
        due = force or self._blocklist_dirty or (now - self._last_blocklist_sync >= interval)
        if not due:
            return

        desired = sorted(self.store.active_ban_ips())

        if self.manual is not None:
            try:
                changed = self.manual.sync(desired)
                if changed:
                    self.reban_all_active()
            except Exception as exc:  # noqa: BLE001
                log.error("同步手动屏蔽列表失败: %s", exc)

        if self.use_file:
            self._sync_file(desired)

        # 从旧的文件模式升级过来时，清空历史 ipfilter.dat，避免过期封禁残留
        if self.blocklist_mode == "manual" and not self._legacy_cleaned:
            self._cleanup_legacy_filter()

        self._blocklist_dirty = False
        self._last_blocklist_sync = now

    def _sync_file(self, desired: List[str]):
        try:
            changed = self.filter.sync(desired)
        except Exception as exc:  # noqa: BLE001
            log.error("同步 IP 过滤器失败: %s", exc)
            return
        prefs_ok = self.filter.prefs_ok(self.qbt)
        first_with_bans = (not self._filter_initialized) and len(desired) > 0
        if changed or (not prefs_ok) or first_with_bans:
            ok = self.filter.reload(self.qbt)
            self._last_reload_ok = ok
            self._last_reload_ts = time.time()
            if ok:
                self.reban_all_active()
            else:
                log.error("IP 过滤器重载失败：请执行 sync-blocklist 或在 GUI 点一次 Reload")
        self._filter_initialized = True

    def _cleanup_legacy_filter(self):
        """旧版本用 ipfilter.dat 持久化；切到手动屏蔽后清空它，防止过期规则残留。"""
        self._legacy_cleaned = True
        if not self.filter.enabled:
            return
        try:
            prefs = self.qbt.preferences()
        except Exception:  # noqa: BLE001
            self._legacy_cleaned = False
            return
        cur = str(prefs.get("ip_filter_path") or "")
        if not cur:
            return
        if os.path.normcase(os.path.normpath(cur)) != os.path.normcase(os.path.normpath(self.filter.path)):
            return
        try:
            with open(self.filter.path, "r", encoding="utf-8", errors="replace") as fh:
                if "QBT-ANTILEECH" not in fh.read():
                    return
        except OSError:
            return
        try:
            self.filter.sync([])
            self.filter.reload(self.qbt, force=True)
            log.info("已清空旧 ipfilter.dat，历史封禁改由手动屏蔽列表接管")
        except Exception as exc:  # noqa: BLE001
            log.warning("清理旧 ipfilter.dat 失败: %s", exc)

    # ---------------- 维护 ----------------
    def housekeeping(self, torrents: Dict, samples: List[Sample]):
        now = time.time()
        if now - self._last_housekeep < 3600:
            return
        self._last_housekeep = now
        hours = float(self.cfg.get("runtime.prune_peer_hours", 12))
        pruned = self.store.prune_peers(now - hours * 3600)
        self.store.prune_peer_ids(now - 48 * 3600)
        self.store.trim_events(200000)
        if pruned:
            log.info("清理过期 Peer 记录 %d 条", pruned)
        if len(self._reban_ts) > 5000:
            self._reban_ts = {k: v for k, v in self._reban_ts.items() if now - v < 3600}

    def write_status(self, torrents: Dict, truncated: int, banned: List[str], lifted: List[str]):
        events = self.store.recent_events(20)
        active = self.store.active_bans()
        status = {
            "updated_at": time.time(),
            "qbt_version": self.qbt.version,
            "dry_run": self.dry_run,
            "torrents": len(torrents),
            "torrents_skipped": truncated,
            "peers_seen": self.stats.get("peers_seen"),
            "unparsed_peers": len(self._unparsed),
            "unparsed_samples": sorted(self._unparsed)[:5],
            "cycles": self.stats.get("cycles"),
            "active_bans": len(active),
            "new_bans": banned,
            "lifted": lifted,
            "last_error": self.stats.get("last_error", ""),
            "blocklist_mode": self.blocklist_mode,
            "manual_entries": (self.manual.last_count if self.manual else None),
            "manual_ok": (self.manual.last_ok if self.manual else None),
            "filter_path": self.filter.path if self.use_file else None,
            "filter_reload_ok": self._last_reload_ok if self.use_file else None,
            "recent_bans": [
                {"ip": b.ip, "score": b.score, "reason": b.reason,
                 "expires_in": max(0, int(b.expires - time.time()))}
                for b in active[:10]
            ],
            "recent_events": events[:10],
        }
        path = self.cfg.status_path
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(status, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
        except OSError as exc:
            log.warning("写入状态文件失败: %s", exc)

    # ---------------- 手工操作 ----------------
    def manual_ban(self, ip: str, reason: str = "manual", hours: int = 24) -> bool:
        addr = coerce_ip(ip)
        if addr is None:
            log.error("非法 IP: %s", ip)
            return False
        key = str(addr)
        expires = time.time() + hours * 3600 if hours > 0 else 0.0
        self.store.add_ban(key, reason, 999.0, time.time(), expires, "manual")
        self.store.record_event(key, "ban", reason, "manual")
        self.ban_cache.add(key)
        self._mark_blocklist_dirty()
        self.ensure_blocklist(force=True)
        log.info("已手工封禁 %s (%s)", key, reason)
        return True

    def manual_unban(self, ip: str, sync: bool = True) -> bool:
        addr = coerce_ip(ip)
        key = str(addr) if addr else ip
        ban = self.store.get_ban(key)
        if not ban:
            log.warning("没有找到封禁记录: %s", key)
            return False
        self.store.deactivate_ban(key)
        self.store.record_event(key, "unban", "手工解除", ban.reason)
        self.ban_cache.discard(key)
        self._mark_blocklist_dirty()
        if sync:
            self.ensure_blocklist(force=True)
        if self.fw.enabled:
            self.fw.unblock(key)
        try:
            self.qbt.unban_peers([key])
        except Exception:  # noqa: BLE001
            pass
        log.info("已解除封禁 %s（已从手动屏蔽列表移除；qB 会话内已建立的连接"
                 "需等对端断开或重启 qB 才会彻底消失）", key)
        return True

    def close(self):
        self.store.close()
