"""配置加载：JSON + 默认值深合并 + 相对路径解析 + 环境变量覆盖。"""

from __future__ import annotations

import copy
import json
import os
from typing import Any, Dict

DEFAULTS: Dict[str, Any] = {
    "qbt": {
        "base_url": "http://127.0.0.1:8080",
        "username": "admin",
        "password": "",
        "api_key": "",
        "verify_tls": True,
        "timeout": 15,
        "max_retries": 3,
        "trust_env_proxy": False,
    },
    "runtime": {
        "interval_seconds": 15,
        "reapply_seconds": 300,
        "max_torrents_per_cycle": 40,
        "prune_peer_hours": 12,
        "data_dir": "./data",
    },
    "detection": {
        # 通用时间/容量阈值
        "min_connected_seconds": 600,
        "window_seconds": 600,
        "window_upload_bytes": 268435456,
        "min_uploaded_bytes": 268435456,
        "long_connection_seconds": 3600,
        # 关键判据：进度长期不增长
        "zero_progress_max": 0.01,
        "max_return_ratio": 0.02,
        # 伪报完成
        "fake_seeder_progress": 0.999,
        "fake_seeder_upload_bytes": 134217728,
        # 打分
        "ban_threshold": 60.0,
        "score_cap": 200.0,
        "score_decay_per_hour": 8.0,
        "score_zero_progress": 45.0,
        "score_window": 30.0,
        "score_fake_seeder": 25.0,
        "score_long_no_return": 40.0,
        "score_fake_client": 35.0,
        "score_peerid_reuse": 35.0,
        "good_peer_credit": 10.0,
        "enable_fake_client_check": True,
        "check_client_version": True,
        "peerid_reuse_ips": 3,
        # 客户端指纹
        "hard_ban_client_patterns": [
            "xunlei", "thunder", "迅雷", "xl0012", "sd0100",
            "qq旋风", "xfplay", "-xl", "-sd01"
        ],
        "hard_ban_peer_id_prefixes": ["-XL0012-", "-SD0100-", "-TX0006-", "-XF0"],
        "client_version_ceiling": {
            "qbittorrent": "5.3.9",
            "utorrent": "3.6.9",
            "bittorrent": "7.11.9",
            "transmission": "4.0.9",
            "deluge": "2.1.9",
            "libtorrent": "2.0.11",
            "vuze": "6.0.0.0",
            "bitcomet": "2.11",
            "tixati": "3.29",
            "bittornado": "0.3.18"
        },
        "client_family_prefix": {
            "qbittorrent": ["-QB"],
            "utorrent": ["-UT"],
            "bittorrent": ["-BT"],
            "transmission": ["-TR"],
            "deluge": ["-DE"],
            "libtorrent": ["-LT"],
            "bitcomet": ["-BC"],
            "tixati": ["-TX"],
            "vuze": ["-AZ"],
            "bittornado": ["-BB"]
        }
    },
    "ban": {
        "duration_seconds": 86400,
        "hard_duration_seconds": 604800,
        "dry_run": False,
        "max_bans": 50000,
        "ipv6_prefix_length": 0
    },
    "blocklist": {
        "mode": "manual",
        "max_entries": 5000,
        "sync_interval_seconds": 60
    },
    "ip_filter": {
        "enabled": True,
        "path": "./data/ipfilter.dat",
        "base_file": "",
        "reload_mode": "toggle",
        "min_reload_interval_seconds": 30
    },
    "firewall": {
        "enabled": False,
        "rule_prefix": "QBT-AntiLeech",
        "group": "qBittorrent AntiLeech"
    },
    "whitelist": {
        "allow_private": True,
        "cidrs": [],
        "ips": []
    },
    "logging": {
        "level": "INFO",
        "file": "",
        "max_bytes": 10485760,
        "backups": 5,
        "console": True
    }
}


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


class Config:
    def __init__(self, data: Dict[str, Any], path: str = None):
        self.data = data
        self.path = os.path.abspath(path) if path else ""
        self.base_dir = os.path.dirname(self.path) if self.path else os.getcwd()

    @classmethod
    def load(cls, path: str) -> "Config":
        if not os.path.isfile(path):
            raise FileNotFoundError("配置文件不存在: %s" % path)
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        cfg = cls(deep_merge(DEFAULTS, raw), path)
        cfg.apply_env()
        cfg.resolve_paths()
        return cfg

    def apply_env(self):
        env = os.environ
        if env.get("QBT_URL"):
            self.data["qbt"]["base_url"] = env["QBT_URL"]
        if env.get("QBT_USER"):
            self.data["qbt"]["username"] = env["QBT_USER"]
        if env.get("QBT_PASS"):
            self.data["qbt"]["password"] = env["QBT_PASS"]

    def _abs(self, value: str) -> str:
        if not value:
            return value
        value = os.path.expanduser(str(value))
        if not os.path.isabs(value):
            value = os.path.join(self.base_dir, value)
        return os.path.normpath(value)

    def resolve_paths(self):
        data_dir = self._abs(self.get("runtime.data_dir") or "./data")
        self.data["runtime"]["data_dir"] = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.data["ip_filter"]["path"] = self._abs(
            self.get("ip_filter.path") or os.path.join(data_dir, "ipfilter.dat")
        )
        base = self.get("ip_filter.base_file")
        self.data["ip_filter"]["base_file"] = self._abs(base) if base else ""
        log_file = self.get("logging.file")
        self.data["logging"]["file"] = self._abs(log_file) if log_file else os.path.join(data_dir, "antileech.log")

    def get(self, dotted: str, default=None):
        cur = self.data
        for part in str(dotted).split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def section(self, name: str) -> Dict[str, Any]:
        return self.get(name, {}) or {}

    @property
    def data_dir(self) -> str:
        return self.get("runtime.data_dir")

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "antileech.db")

    @property
    def status_path(self) -> str:
        return os.path.join(self.data_dir, "status.json")
