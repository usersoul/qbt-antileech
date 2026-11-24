"""Peer 行为评分引擎。

判定核心不是"客户端名字像不像迅雷"，而是 **上传出去了多少 / 对方回报了多少**：
qBittorrent 的 peers 数据里，uploaded 是我们上传给该 Peer 的字节数，
downloaded 是我们从该 Peer 下载到的字节数。一个正常 BT 客户端在当前种子上
不会"只收不给"，所以用 (uploaded 很大, progress 停滞, downloaded≈0) 这组
组合特征做判据，比单看客户端名称更难被伪装绕过。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .store import PeerState
from .util import normalize_ip

log = logging.getLogger(__name__)

_VERSION_RE = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9\.\-\s\+]*?)\s+(?P<ver>\d+(?:\.\d+){0,3})\b")


@dataclass
class Sample:
    ip: str
    port: int
    infohash: str
    raw_ip: str = ""
    client: str = ""
    peer_id: str = ""
    progress: float = 0.0
    downloaded: int = 0
    uploaded: int = 0
    dl_speed: int = 0
    up_speed: int = 0
    connection: str = ""
    flags: str = ""
    ts: float = 0.0


@dataclass
class EvalResult:
    score: float
    reasons: List[str] = field(default_factory=list)
    hard: bool = False
    state: Optional[PeerState] = None


def _ver_tuple(text: str) -> Tuple[int, ...]:
    parts = []
    for p in str(text).split("."):
        m = re.match(r"\d+", p)
        parts.append(int(m.group()) if m else 0)
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])


def parse_client(client: str) -> Tuple[str, str]:
    """'qBittorrent 5.3.0' -> ('qbittorrent', '5.3.0')"""
    m = _VERSION_RE.match((client or "").strip())
    if not m:
        return "", ""
    return m.group("name").strip().lower().replace(" ", ""), m.group("ver")


def check_client_fingerprint(sample: Sample, det: Dict) -> Tuple[float, List[str]]:
    """客户端伪装检测（R6）。

    关闭方式：
      detection.enable_fake_client_check = false → 整条 R6 关闭
      detection.check_client_version     = false → 只关"版本超出已知上限"这一项
    （PeerID 前缀不符、指纹为空仍会生效。）
    """
    if not det.get("enable_fake_client_check", True):
        return 0.0, []

    score = 0.0
    reasons: List[str] = []
    client = (sample.client or "").strip()
    peer_id = (sample.peer_id or "").strip()
    family, version = parse_client(client)

    if peer_id and family:
        expected = (det.get("client_family_prefix") or {}).get(family)
        if expected:
            upper = peer_id.upper()
            if not any(upper.startswith(p.upper()) for p in expected):
                score += float(det.get("score_fake_client", 35))
                reasons.append("R6:客户端伪装(自称%s,PeerID=%s)" % (family, peer_id[:9]))

    if det.get("check_client_version", True):
        ceiling_map = det.get("client_version_ceiling") or {}
        ceiling = ceiling_map.get(family)
        if family and version and ceiling:
            if _ver_tuple(version) > _ver_tuple(str(ceiling)):
                score += float(det.get("score_fake_client", 35))
                reasons.append("R6:版本不可能(%s %s > 上限 %s)" % (family, version, ceiling))

    if not client and sample.uploaded > 64 * 1024 * 1024:
        score += 20.0
        reasons.append("R6:客户端指纹为空但持续吸量")

    return score, reasons


def evaluate(cfg: Dict, sample: Sample, prev: Optional[PeerState],
             now: float, peerid_ip_count: int = 0) -> EvalResult:
    """返回本周期新增分数与原因。分数叠加、随时间衰减。"""
    det = cfg["detection"]
    reasons: List[str] = []
    delta = 0.0
    hard = False

    # ---- 会话重置：Peer 重连后计数器会归零 ----
    reset = prev is None or sample.uploaded < prev.uploaded or sample.downloaded < prev.downloaded
    if reset:
        state = PeerState(
            ip=sample.ip, infohash=sample.infohash, port=sample.port,
            client=sample.client, peer_id=sample.peer_id,
            first_seen=now, last_seen=now, downloaded=sample.downloaded,
            uploaded=sample.uploaded, progress=sample.progress,
            score=0.0, score_ts=now, win_start=now, win_up=0, win_down=0,
            strikes=0, samples=1,
        )
    else:
        decay_hours = max(0.0, (now - (prev.score_ts or now)) / 3600.0)
        decayed = max(0.0, prev.score - float(det.get("score_decay_per_hour", 8.0)) * decay_hours)
        state = PeerState(
            ip=sample.ip, infohash=sample.infohash, port=sample.port,
            client=sample.client, peer_id=sample.peer_id,
            first_seen=prev.first_seen, last_seen=now,
            downloaded=sample.downloaded, uploaded=sample.uploaded,
            progress=sample.progress, score=decayed, score_ts=now,
            win_start=prev.win_start or now, win_up=prev.win_up, win_down=prev.win_down,
            strikes=prev.strikes, samples=prev.samples + 1,
        )

    connected = max(0.0, now - state.first_seen)

    # ---- R1 指纹硬封禁（迅雷系 / 已知吸血）----
    blob = ("%s %s" % (sample.client or "", sample.peer_id or "")).lower()
    for pat in det.get("hard_ban_client_patterns", []):
        p = str(pat).lower()
        if p and p in blob:
            reasons.append("R1:命中吸血客户端指纹(%s)" % pat)
            delta += 100.0
            hard = True
            break
    if not hard and sample.peer_id:
        upper = sample.peer_id.upper()
        for prefix in det.get("hard_ban_peer_id_prefixes", []):
            if upper.startswith(str(prefix).upper()):
                reasons.append("R1:命中吸血PeerID前缀(%s)" % prefix)
                delta += 100.0
                hard = True
                break

    # ---- R2 核心判据：进度停滞 + 只收不回 ----
    upload_total = sample.uploaded
    return_ratio = (sample.downloaded / upload_total) if upload_total > 0 else 0.0
    stalled = sample.progress <= float(det.get("zero_progress_max", 0.01))
    if (connected >= float(det.get("min_connected_seconds", 600))
            and upload_total >= int(det.get("min_uploaded_bytes", 268435456))
            and stalled
            and return_ratio <= float(det.get("max_return_ratio", 0.02))):
        delta += float(det.get("score_zero_progress", 45))
        reasons.append("R2:下载进度%.0f%%停滞，上传%.1fMiB仅回收%.2f%%"
                       % (sample.progress * 100, upload_total / 1048576.0, return_ratio * 100))

    # ---- R3 窗口突发：短时间内持续被吸、对方零回报 ----
    if not reset and prev is not None:
        state.win_up += max(0, sample.uploaded - prev.uploaded)
        state.win_down += max(0, sample.downloaded - prev.downloaded)
    if now - state.win_start >= float(det.get("window_seconds", 600)):
        if (state.win_up >= int(det.get("window_upload_bytes", 268435456))
                and state.win_down <= state.win_up * float(det.get("max_return_ratio", 0.02))
                and stalled):
            delta += float(det.get("score_window", 30))
            reasons.append("R3:%d秒内被吸%.1fMiB且零回报"
                           % (now - state.win_start, state.win_up / 1048576.0))
        state.win_start = now
        state.win_up = 0
        state.win_down = 0

    # ---- R4 伪报完成进度 ----
    if (sample.progress >= float(det.get("fake_seeder_progress", 0.999))
            and upload_total >= int(det.get("fake_seeder_upload_bytes", 134217728))):
        delta += float(det.get("score_fake_seeder", 25))
        reasons.append("R4:伪报完成(进度100%%仍被持续上传%.1fMiB)" % (upload_total / 1048576.0))

    # ---- R5 长时间单向吸血 ----
    if (connected >= float(det.get("long_connection_seconds", 3600))
            and upload_total >= int(det.get("min_uploaded_bytes", 268435456)) * 2
            and sample.downloaded == 0
            and sample.progress < 0.5):
        delta += float(det.get("score_long_no_return", 40))
        reasons.append("R5:连接%.0f分钟，上传%.1fMiB，下载0"
                       % (connected / 60.0, upload_total / 1048576.0))

    # ---- R6 客户端伪装 ----
    fs, fr = check_client_fingerprint(sample, det)
    if fs:
        delta += fs
        reasons.extend(fr)

    # ---- R7 peer_id 农场：同一 PeerID 出现在多个 IP ----
    # if peerid_ip_count >= int(det.get("peerid_reuse_ips", 3)):
    #     delta += float(det.get("score_peerid_reuse", 35))
    #     reasons.append("R7:同一PeerID出现在%d个IP上" % peerid_ip_count)

    # ---- 正常互惠行为抵扣 ----
    if (sample.downloaded > 0 and upload_total > 0
            and sample.downloaded >= upload_total * 0.5):
        delta -= float(det.get("good_peer_credit", 10))
        reasons.append("BONUS:双向互惠，抵扣分数")

    state.score = min(float(det.get("score_cap", 200)), max(0.0, state.score + delta))
    if reasons:
        state.strikes = prev.strikes + 1 if prev else 1
    return EvalResult(score=state.score, reasons=reasons, hard=hard, state=state)
