"""离线自测：用本地假 qBittorrent WebUI 跑通 采集→评分→封禁→手动屏蔽列表→解封→到期恢复。

运行: python tests/smoke_test.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from antileech.config import Config, deep_merge, DEFAULTS
from antileech.engine import Engine

HASH = "0123456789abcdef0123456789abcdef01234567"

STATE = {
    "peers": {},
    "bans": [],
    "prefs": {"ip_filter_enabled": False, "ip_filter_path": "",
              "banned_IPs": "8.8.8.8"},
    "pref_calls": [],
    "version": "5.3.0",
}
COOKIE = "SID=test123"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, text, code=200, cookie=False):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", COOKIE + "; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        if path == "/api/v2/app/version":
            return self._text(STATE["version"])
        if path == "/api/v2/transfer/info":
            return self._json({"connection_status": "connected", "dl_info_speed": 0})
        if path == "/api/v2/app/preferences":
            return self._json(STATE["prefs"])
        if path == "/api/v2/sync/maindata":
            return self._json({"rid": 1, "torrents": {
                HASH: {"hash": HASH, "name": "test", "up_speed": 1048576,
                       "dl_speed": 0, "num_leechs": len(STATE["peers"]),
                       "state": "uploading"}
            }})
        if path == "/api/v2/sync/torrentPeers":
            return self._json({"rid": 1, "peers": STATE["peers"]})
        if path == "/api/v2/torrents/peers":
            return self._json({"peers": STATE["peers"]})
        return self._text("not found", 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8")
        form = parse_qs(raw)

        if parsed.path == "/api/v2/auth/login":
            if form.get("username", [""])[0] == "admin" and form.get("password", [""])[0] == "pass":
                return self._text("Ok.", 200, cookie=True)
            return self._text("Fails.", 200)

        if "SID=test123" not in (self.headers.get("Cookie") or ""):
            return self._text("forbidden", 403)

        if parsed.path == "/api/v2/transfer/banPeers":
            peers = form.get("peers", [""])[0]
            STATE["bans"].extend([p for p in peers.split("|") if p])
            return self._text("")
        if parsed.path == "/api/v2/app/setPreferences":
            payload = json.loads(form.get("json", ["{}"])[0])
            STATE["pref_calls"].append(payload)
            if "banned_IPs" in payload:
                value = payload["banned_IPs"]
                # qB 对数组会 toString() 成空串，如实模拟
                payload["banned_IPs"] = "" if isinstance(value, list) else str(value)
            STATE["prefs"].update(payload)
            return self._text("")
        if parsed.path == "/api/v2/transfer/unbanPeers":
            return self._text("not found", 404)
        return self._text("not found", 404)




def banned_lines():
    raw = STATE["prefs"].get("banned_IPs") or ""
    if isinstance(raw, list):
        raw = "\n".join(raw)
    return [x for x in str(raw).split("\n") if x]

def peer(ip, port, client, peer_id="", progress=0.0, downloaded=0, uploaded=0):
    return {"ip": ip, "port": port, "client": client, "peer_id": peer_id,
            "progress": progress, "downloaded": downloaded, "uploaded": uploaded,
            "dl_speed": 0, "up_speed": 1024, "connection": "BT", "flags": ""}


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    tmp = tempfile.mkdtemp(prefix="antileech-test-")
    cfg_path = os.path.join(tmp, "config.json")
    overrides = {
        "qbt": {"base_url": "http://127.0.0.1:%d" % port, "username": "admin", "password": "pass"},
        "runtime": {"interval_seconds": 1, "data_dir": os.path.join(tmp, "data"),
                    "max_torrents_per_cycle": 10, "reapply_seconds": 1},
        "detection": {
            "min_connected_seconds": 0, "min_uploaded_bytes": 1000,
            "window_seconds": 1, "window_upload_bytes": 1000,
            "ban_threshold": 40.0, "score_decay_per_hour": 0.0,
        },
        "ban": {"duration_seconds": 3600, "hard_duration_seconds": 3600},
        "ip_filter": {"enabled": True, "path": os.path.join(tmp, "data", "ipfilter.dat")},
        "logging": {"console": False, "file": "", "level": "WARNING"},
    }
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump(deep_merge(DEFAULTS, overrides), fh, ensure_ascii=False)

    cfg = Config.load(cfg_path)
    engine = Engine(cfg)

    # 场景：迅雷硬封 / IPv6 零进度吸血 / 正常互惠用户
    STATE["peers"] = {
        "1.2.3.4:6881": peer("1.2.3.4", 6881, "Xunlei 0.0.0", "-XL0012-ABCDEF", 0.42, 0, 0),
        "2001:db8::5:6882": peer("2001:db8::5", 6882, "qBittorrent 5.3.0", "-qB5300-", 0.0, 0, 3_000_000),
        "9.9.9.9:6883": peer("9.9.9.9", 6883, "qBittorrent 4.6.2", "-qB4620-", 0.85, 900_000, 1_000_000),
    }

    engine.cycle()
    bans = {b.ip for b in engine.store.active_bans()}
    assert "1.2.3.4" in bans, "迅雷客户端应被硬封禁，实际: %s" % bans
    assert "2001:db8::5" in bans, "IPv6 零进度吸血应被封禁，实际: %s" % bans
    assert "9.9.9.9" not in bans, "正常互惠用户不应被封禁"

    # 核心：走 qB 的"手动屏蔽 IP 地址"列表，而不是 ipfilter.dat
    listed = banned_lines()
    assert "1.2.3.4" in listed, "迅雷 IP 未写入手动屏蔽列表: %s" % listed
    assert isinstance(STATE["prefs"].get("banned_IPs"), str), "banned_IPs 必须是字符串"
    assert "2001:db8::5" in listed, "IPv6 吸血 IP 未写入手动屏蔽列表: %s" % listed
    assert "9.9.9.9" not in listed, "正常用户被误写入手动屏蔽列表"
    assert "8.8.8.8" in listed, "用户原有的手工条目被覆盖"
    assert any(x.startswith("1.2.3.4:") for x in STATE["bans"]), "未下发 banPeers 断开现有连接"
    assert not os.path.exists(cfg.get("ip_filter.path")), "manual 模式不应再写 ipfilter.dat"
    assert STATE["prefs"]["ip_filter_enabled"] is False, "manual 模式不应改动 IP 过滤器开关"
    print("[OK] 采集/评分/封禁/手动屏蔽列表 全部生效（用户条目保留、不写文件）")

    # 误封解除
    assert engine.manual_unban("9.9.9.9") is False, "未封禁的 IP 不应返回成功"
    assert engine.manual_unban("2001:db8::5") is True
    listed = banned_lines()
    assert "2001:db8::5" not in listed, "解封后手动屏蔽列表未更新"
    assert "8.8.8.8" in listed, "解封时误删了用户手工条目"
    print("[OK] 手工解封并即时同步手动屏蔽列表")

    # 自动到期恢复
    engine.store.add_ban("1.2.3.4", "test", 100, time.time(), time.time() + 1, "auto")
    engine.ban_cache.add("1.2.3.4")
    engine._blocklist_dirty = True
    time.sleep(1.2)
    lifted = engine.expire_bans()
    engine.ensure_blocklist(force=True)
    assert "1.2.3.4" in lifted, "到期封禁应自动解除"
    listed = banned_lines()
    assert "1.2.3.4" not in listed, "到期后手动屏蔽列表未清理"
    print("[OK] 封禁到期自动解除并回收")

    # 状态文件
    engine.write_status({}, 0, [], [])
    status = json.load(open(cfg.status_path, encoding="utf-8"))
    assert status["qbt_version"] == "5.3.0"
    assert status["blocklist_mode"] == "manual"
    print("[OK] 状态文件输出正常: active_bans=%s" % status["active_bans"])

    server.shutdown()
    engine.close()
    print("\n全部自测通过。")


if __name__ == "__main__":
    main()