"""IPv4-mapped IPv6（::ffff:a.b.c.d）地址的封禁回归测试。

qBittorrent 在双栈 socket 下会把 IPv4 peer 报成 ::ffff:58.219.53.198，
必须把两种写法一起下发，否则 banPeers 匹配不到连接、banned_IPs 也可能不命中。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import smoke_test as st
from antileech.config import Config, deep_merge, DEFAULTS
from antileech.engine import Engine
from antileech.util import ban_forms, coerce_ip, is_private


def lines(value):
    raw = value if isinstance(value, str) else "\n".join(value or [])
    return [x for x in str(raw).split("\n") if x]


def make_engine(tmp, port):
    cfg = deep_merge(DEFAULTS, {
        "qbt": {"base_url": "http://127.0.0.1:%d" % port, "username": "admin",
                "password": "pass"},
        "runtime": {"data_dir": os.path.join(tmp, "data"), "reapply_seconds": 1},
        "detection": {"min_connected_seconds": 0, "min_uploaded_bytes": 0,
                      "ban_threshold": 40},
        "logging": {"console": False, "file": ""},
    })
    path = os.path.join(tmp, "config.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, ensure_ascii=False)
    return Engine(Config.load(path))


def main():
    # ---- 纯函数层 ----
    assert ban_forms("58.219.53.198", "::ffff:58.219.53.198") == \
        ["58.219.53.198", "::ffff:58.219.53.198"]
    assert "::ffff:1.2.3.4" in ban_forms("1.2.3.4", "")
    assert coerce_ip("::ffff:58.219.53.198") == __import__("ipaddress").ip_address("58.219.53.198")
    assert str(coerce_ip("0:0:0:0:0:ffff:1.2.3.4")) == "1.2.3.4"
    assert coerce_ip("::ffff:fe80::1") is None
    assert is_private(coerce_ip("::ffff:192.168.1.50")) is True
    print("[OK] coerce_ip / ban_forms / 内网映射判定")

    server = ThreadingHTTPServer(("127.0.0.1", 0), st.Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    tmp = tempfile.mkdtemp(prefix="mapped-test-")
    st.STATE["prefs"] = {"ip_filter_enabled": False, "ip_filter_path": "",
                         "banned_IPs": "8.8.8.8"}
    st.STATE["bans"] = []
    st.STATE["pref_calls"] = []

    engine = make_engine(tmp, port)
    st.STATE["peers"] = {
        # 1) 双栈映射写法的迅雷：必须被封，且两种形式都下发
        "::ffff:58.219.53.198:6881": st.peer("::ffff:58.219.53.198", 6881,
                                             "Xunlei 0.0.3", "-SD0100-X", 0.3, 0, 5_000_000),
        # 2) 映射到内网：白名单，绝不能封
        "::ffff:192.168.1.50:6882": st.peer("::ffff:192.168.1.50", 6882,
                                           "Xunlei 0.0.3", "-SD0100-Y", 0.3, 0, 5_000_000),
        # 3) 写法解析不出：跳过但要被计入 unparsed
        "::ffff:fe80::1:6883": st.peer("::ffff:fe80::1", 6883,
                                       "Xunlei 0.0.3", "-SD0100-Z", 0.3, 0, 5_000_000),
    }

    engine.cycle()

    banned = {b.ip for b in engine.store.active_bans()}
    assert "58.219.53.198" in banned, "映射地址未被识别为封禁对象: %s" % banned
    assert "192.168.1.50" not in banned, "内网映射地址被误封"
    print("[OK] ::ffff: 形式的吸血客户端能识别并封禁（内网映射不误伤）")

    listed = lines(st.STATE["prefs"].get("banned_IPs"))
    assert "58.219.53.198" in listed, "banned_IPs 缺少纯 IPv4 形式: %s" % listed
    assert "::ffff:58.219.53.198" in listed, "banned_IPs 缺少 IPv4-mapped 形式: %s" % listed
    assert "8.8.8.8" in listed, "用户手工条目被覆盖"
    assert "192.168.1.50" not in listed and "::ffff:192.168.1.50" not in listed
    print("[OK] 两种地址写法都写入了手动屏蔽列表")

    eps = set(st.STATE["bans"])
    assert "58.219.53.198:6881" in eps, "banPeers 缺少 IPv4 端点: %s" % eps
    assert "::ffff:58.219.53.198:6881" in eps, "banPeers 缺少映射端点(断不开现有连接): %s" % eps
    print("[OK] banPeers 同时下发两种端点，可断开现有连接")

    status_path = os.path.join(tmp, "data", "status.json")
    status = json.load(open(status_path, encoding="utf-8"))
    assert status["unparsed_peers"] >= 1, "无法解析的地址未暴露: %s" % status
    assert any("fe80" in x for x in status["unparsed_samples"])
    print("[OK] 解析失败的地址不再静默丢弃，status 可见: %s" % status["unparsed_samples"])

    # 别名持久化：重启后手工封禁同一 IP 仍会带上映射写法
    alias = json.loads(engine.store.kv_get("alias:58.219.53.198", "[]"))
    assert "::ffff:58.219.53.198" in alias, "别名未持久化: %s" % alias
    engine2 = make_engine(tmp, port)
    assert "::ffff:58.219.53.198" in engine2._expand_forms("58.219.53.198")
    print("[OK] 进程重启后仍知道该 IP 的映射写法")

    # 解封：两种写法一起移除
    assert engine2.manual_unban("58.219.53.198") is True
    listed = lines(st.STATE["prefs"].get("banned_IPs"))
    assert "58.219.53.198" not in listed and "::ffff:58.219.53.198" not in listed, listed
    assert "8.8.8.8" in listed
    print("[OK] 解封时两种写法一并移除")

    server.shutdown()
    print("\nIPv4-mapped 地址处理测试全部通过。")


if __name__ == "__main__":
    main()
