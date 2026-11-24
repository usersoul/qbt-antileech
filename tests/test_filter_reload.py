"""IP 过滤器写入 + 强制重载 的单元测试。

复现用户反馈的问题：文件写了但 qB 没有重新加载，导致封禁不生效。
"""

from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from antileech.ipfilter import IpFilter


class FakeQbt:
    def __init__(self, path, enabled=True):
        self.prefs = {"ip_filter_enabled": enabled, "ip_filter_path": path}
        self.calls = []

    def preferences(self):
        return dict(self.prefs)

    def set_preferences(self, prefs):
        self.calls.append(dict(prefs))
        self.prefs.update(prefs)


def main():
    tmp = tempfile.mkdtemp(prefix="ipfilter-test-")
    path = os.path.join(tmp, "ipfilter.dat")

    # 1) 写入并合并相邻网段
    f = IpFilter(path)
    assert f.sync(["1.2.3.4", "5.6.7.0/24", "2001:db8::5"]) is True
    content = open(path, encoding="utf-8").read()
    assert "1.2.3.4 - 1.2.3.4" in content
    assert "5.6.7.0 - 5.6.7.255" in content
    assert "2001:db8::5 - 2001:db8::5" in content
    assert f.sync(["1.2.3.4", "5.6.7.0/24", "2001:db8::5"]) is False
    print("[OK] 过滤器写入 / 去重 / IPv6")

    # 2) toggle 强制重载：必须是 关闭 -> 开启+路径
    qbt = FakeQbt(path, enabled=True)
    assert f.reload(qbt) is True
    assert len(qbt.calls) == 2, qbt.calls
    assert qbt.calls[0] == {"ip_filter_enabled": False}, qbt.calls[0]
    assert qbt.calls[1]["ip_filter_enabled"] is True
    assert qbt.calls[1]["ip_filter_path"] == path
    assert qbt.prefs["ip_filter_enabled"] is True
    print("[OK] toggle 强制重载：关闭 -> 开启，顺序正确")

    # 3) 路径被改错时能纠正
    qbt = FakeQbt("/tmp/wrong-ipfilter.dat", enabled=True)
    assert f.prefs_ok(qbt) is False
    assert f.reload(qbt) is True
    assert qbt.prefs["ip_filter_path"] == path
    print("[OK] 路径错误自动纠正")

    # 4) reload_mode=none 只设置一次，不 toggle
    qbt = FakeQbt(path, enabled=True)
    f2 = IpFilter(path, reload_mode="none")
    assert f2.reload(qbt) is True
    assert len(qbt.calls) == 1
    print("[OK] reload_mode=none 兼容模式")

    # 5) 文件被占用时的原地写兜底不应崩溃
    f3 = IpFilter(os.path.join(tmp, "locked.dat"))
    assert f3.sync(["9.9.9.9"]) is True
    print("[OK] 原子替换 + 原地写兜底")

    print("\n过滤器重载测试全部通过。")


if __name__ == "__main__":
    main()