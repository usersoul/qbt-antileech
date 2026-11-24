"""手动屏蔽列表（banned_IPs）单元测试。

模拟 qB 的真实语义：banned_IPs 是换行分隔的字符串；传 JSON 数组会被转成空串。
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from antileech.blocklist import ManualBanList
from antileech.store import Store


class FakeQbt:
    def __init__(self, entries=None):
        self.prefs = {"banned_IPs": "\n".join(entries or [])}
        self.writes = []

    def preferences(self):
        return {"banned_IPs": self.prefs.get("banned_IPs", "")}

    def set_preferences(self, prefs):
        self.writes.append(dict(prefs))
        if "banned_IPs" in prefs:
            value = prefs["banned_IPs"]
            # qB 对数组会 toString() 成空串，这里如实模拟
            self.prefs["banned_IPs"] = "" if isinstance(value, list) else str(value)

    def listed(self):
        return [x for x in self.prefs["banned_IPs"].split("\n") if x]


def main():
    tmp = tempfile.mkdtemp(prefix="manualban-test-")
    store = Store(os.path.join(tmp, "t.db"))
    qbt = FakeQbt(["8.8.8.8"])          # 用户自己手工加的条目

    m = ManualBanList(qbt, store, max_entries=10)
    assert m.sync(["1.2.3.4", "2001:db8::5"]) is True
    listed = qbt.listed()
    assert "8.8.8.8" in listed, "用户条目被覆盖"
    assert "1.2.3.4" in listed and "2001:db8::5" in listed
    assert len(qbt.writes) == 1 and m.last_ok is True
    # 关键回归：必须是字符串而不是数组
    assert isinstance(qbt.writes[0]["banned_IPs"], str), "banned_IPs 必须以字符串下发"
    print("[OK] 以字符串写入，保留用户手工条目")

    # 幂等：内容一致时不再写
    assert m.sync(["1.2.3.4", "2001:db8::5"]) is False
    assert len(qbt.writes) == 1
    print("[OK] 内容未变时不重复写偏好")

    # 解封/到期：只移除本系统的条目
    assert m.sync(["1.2.3.4"]) is True
    listed = qbt.listed()
    assert "2001:db8::5" not in listed
    assert "1.2.3.4" in listed and "8.8.8.8" in listed
    print("[OK] 移除过期条目且不误删用户条目")

    # 进程重启后仍知道哪些条目是自己写的
    m2 = ManualBanList(qbt, store, max_entries=10)
    assert m2.sync(["1.2.3.4"]) is False
    assert len(qbt.writes) == 2
    print("[OK] 重启后 owned 状态从 KV 恢复")

    # 清空：只清自己的，保留用户的
    m2.force_remove_all()
    assert qbt.listed() == ["8.8.8.8"]
    print("[OK] force_remove_all 保留用户条目")

    # 读回是空字符串时不应崩溃
    qbt2 = FakeQbt([])
    m3 = ManualBanList(qbt2, store, max_entries=10)
    assert m3.sync([]) is False
    print("[OK] 空列表幂等")

    store.close()
    print("\n手动屏蔽列表测试全部通过。")


if __name__ == "__main__":
    main()