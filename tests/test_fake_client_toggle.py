"""R6 客户端指纹检测的开关测试。"""

import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from antileech.config import DEFAULTS
from antileech.rules import Sample, check_client_fingerprint


def det(**over):
    d = copy.deepcopy(DEFAULTS["detection"])
    d.update(over)
    return d


def sample(client, peer_id="", uploaded=0):
    return Sample(ip="1.2.3.4", port=6881, infohash="x", client=client,
                  peer_id=peer_id, uploaded=uploaded)


def main():
    # 默认：qBittorrent 9.9.9 超过上限 5.3.9 -> 命中
    s = sample("qBittorrent 9.9.9")
    score, reasons = check_client_fingerprint(s, det())
    assert score > 0 and any("版本" in r for r in reasons), (score, reasons)
    print("[OK] 默认开启版本上限检测")

    # 关闭版本检测：不再命中
    score, reasons = check_client_fingerprint(s, det(check_client_version=False))
    assert score == 0 and not reasons, (score, reasons)
    print("[OK] check_client_version=false 关闭版本上限识别")

    # 但 PeerID 前缀不符仍然生效
    s2 = sample("qBittorrent 4.6.2", "-XL0012-ABCDEF")
    score, reasons = check_client_fingerprint(s2, det(check_client_version=False))
    assert score > 0 and any("伪装" in r for r in reasons), (score, reasons)
    print("[OK] 只关版本检测时，PeerID 伪装仍生效")

    # 整条 R6 关闭
    score, reasons = check_client_fingerprint(s2, det(enable_fake_client_check=False))
    assert score == 0 and not reasons
    score, reasons = check_client_fingerprint(s, det(enable_fake_client_check=False))
    assert score == 0 and not reasons
    print("[OK] enable_fake_client_check=false 关闭整条 R6")

    # 上限写成 null / 空字典不应崩溃
    d = det()
    d["client_version_ceiling"] = None
    assert check_client_fingerprint(s, d)[0] == 0
    d = det()
    d["client_version_ceiling"] = {}
    assert check_client_fingerprint(s, d)[0] == 0
    print("[OK] 上限配置为 null / {} 时安全跳过")

    print("\nR6 开关测试全部通过。")


if __name__ == "__main__":
    main()