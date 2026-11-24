"""qBittorrent WebUI API v2 客户端（适配 4.6+ / 5.x，含 5.3.0）。"""

from __future__ import annotations

import json
import logging
import time
from typing import Dict, Iterable, List, Optional

import requests

log = logging.getLogger(__name__)

API = "/api/v2"


class QbtError(RuntimeError):
    pass


class QbtAuthError(QbtError):
    pass


class QbtClient:
    def __init__(self, base_url: str, username: str, password: str,
                 timeout: float = 15.0, verify: bool = True,
                 max_retries: int = 3, trust_env: bool = False,
                 api_key: str = ""):
        self.base_url = str(base_url).rstrip("/")
        self.username = username
        self.password = password
        self.api_key = (api_key or "").strip()
        self.timeout = float(timeout)
        self.verify = bool(verify)
        self.max_retries = max(1, int(max_retries))
        self.session = requests.Session()
        self.session.trust_env = bool(trust_env)
        # qBittorrent 的 CSRF 校验会检查 Referer / Origin
        self.session.headers.update({
            "Referer": self.base_url + "/",
            "Origin": self.base_url,
            "User-Agent": "qbt-antileech/1.0",
        })
        self.logged_in = False
        self.version: Optional[str] = None

    # ---------------- 底层请求 ----------------
    def _url(self, path: str) -> str:
        return self.base_url + path

    def _send(self, method: str, path: str, **kwargs) -> requests.Response:
        last_exc = None
        for attempt in range(self.max_retries):
            try:
                return self.session.request(
                    method, self._url(path), timeout=self.timeout,
                    verify=self.verify, **kwargs
                )
            except requests.RequestException as exc:
                last_exc = exc
                if attempt + 1 < self.max_retries:
                    time.sleep(min(2.0 ** attempt, 5.0))
        raise QbtError("请求 qBittorrent 失败: %s" % last_exc)

    def _has_sid(self) -> bool:
        try:
            return any(c.name == "SID" for c in self.session.cookies)
        except Exception:  # noqa: BLE001
            return False

    def _verify_session(self) -> bool:
        """直接探测一个需要认证的只读接口，确认会话真的可用。"""
        resp = self._send("GET", API + "/app/version")
        return resp.status_code == 200 and bool((resp.text or "").strip())

    def login(self) -> bool:
        """兼容 qBittorrent 4.x~5.1（200 + "Ok."）与 5.2+（204 No Content）。

        5.2.0 起 /api/v2/auth/login 成功时返回 204 且没有响应体，
        因此不能再拿响应文本是否等于 "Ok." 作为成功条件。
        """
        self.logged_in = False

        # 5.2+ 支持 WebUI 里生成的 API Key，优先使用（不受密码/204 变化影响）
        if self.api_key:
            self.session.headers["Authorization"] = "Bearer " + self.api_key
            if self._verify_session():
                self.logged_in = True
                log.info("使用 API Key 认证成功")
                return True
            self.session.headers.pop("Authorization", None)
            raise QbtAuthError("API Key 无效：请在 qBittorrent 5.2+ 的 WebUI 设置中生成 API Key")

        resp = self._send("POST", API + "/auth/login",
                          data={"username": self.username, "password": self.password})
        code = resp.status_code
        text = (resp.text or "").strip()

        if code in (401, 403):
            raise QbtAuthError(
                "WebUI 返回 %d：账号或密码错误、来源校验失败，或本机 IP 已被 qBittorrent 临时封禁" % code)

        if code == 204:
            # qBittorrent 5.2+ 的成功响应
            self.logged_in = True
            if self._verify_session():
                log.info("登录成功（qBittorrent 5.2+ 返回 204 No Content）")
                return True
            self.logged_in = False
            raise QbtAuthError("登录返回 204 但会话校验失败，请确认地址/端口确实指向 qBittorrent WebUI")

        if code != 200:
            raise QbtAuthError("登录失败: HTTP %s, %s" % (code, text[:120]))
        if text == "Fails.":
            raise QbtAuthError("账号或密码错误（WebUI 返回 Fails.）")
        if text == "Ok." or self._has_sid():
            self.logged_in = True
            log.debug("WebUI 登录成功")
            return True

        # 少数版本/反代会返回空的 200，用会话探测做最终判定
        self.logged_in = True
        if self._verify_session():
            log.debug("WebUI 登录成功（已校验会话）")
            return True
        self.logged_in = False
        raise QbtAuthError("无法识别的登录响应: HTTP %s, %r" % (code, text[:120]))

    def _call(self, method: str, path: str, **kwargs) -> requests.Response:
        if not self.logged_in:
            self.login()
        resp = self._send(method, path, **kwargs)
        if resp.status_code == 403:
            log.info("WebUI 会话失效，重新登录")
            self.login()
            resp = self._send(method, path, **kwargs)
        if resp.status_code >= 400:
            raise QbtError("%s %s -> HTTP %s" % (method, path, resp.status_code))
        return resp

    # ---------------- 业务接口 ----------------
    def app_version(self) -> str:
        self.version = self._call("GET", API + "/app/version").text.strip()
        return self.version

    def transfer_info(self) -> Dict:
        return self._call("GET", API + "/transfer/info").json()

    def maindata(self, rid: int = 0) -> Dict:
        return self._call("GET", API + "/sync/maindata", params={"rid": rid}).json()

    def torrent_peers(self, infohash: str) -> Dict[str, Dict]:
        """返回 { "ip:port": {peer 字段} }。
        优先使用 sync/torrentPeers（全量、稳定），失败回退 torrents/peers。"""
        try:
            data = self._call("GET", API + "/sync/torrentPeers",
                              params={"hash": infohash, "rid": 0}).json()
        except QbtError:
            data = self._call("GET", API + "/torrents/peers",
                              params={"hash": infohash}).json()
        return data.get("peers") or {}

    def preferences(self) -> Dict:
        return self._call("GET", API + "/app/preferences").json()

    def set_preferences(self, prefs: Dict):
        self._call("POST", API + "/app/setPreferences",
                   data={"json": json.dumps(prefs)})

    def ban_peers(self, endpoints: Iterable[str]) -> int:
        """会话级封禁，立即生效（qB 重启后需重新下发，本系统会自动补发）。"""
        items: List[str] = [e for e in endpoints if e]
        sent = 0
        for i in range(0, len(items), 200):
            chunk = items[i:i + 200]
            self._call("POST", API + "/transfer/banPeers",
                       data={"peers": "|".join(chunk)})
            sent += len(chunk)
        return sent

    def unban_peers(self, ips: Iterable[str]) -> bool:
        """尽力解除会话级封禁。部分版本没有该接口，返回 False。"""
        items = [str(i) for i in ips if i]
        if not items:
            return False
        try:
            self._call("POST", API + "/transfer/unbanPeers",
                       data={"peers": "|".join(items)})
            return True
        except QbtError:
            return False
