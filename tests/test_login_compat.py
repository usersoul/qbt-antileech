"""针对 qBittorrent 5.2+ 登录返回 204 的兼容性测试。"""

import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from antileech.config import Config, deep_merge, DEFAULTS
from antileech.qbt import QbtAuthError, QbtClient

MODE = {"value": "204"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        if self.path != "/api/v2/auth/login":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if MODE["value"] == "204":
            self.send_response(204)
            self.send_header("Set-Cookie", "SID=abc123; Path=/; HttpOnly")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"Fails." if MODE["value"] == "fails" else b"Ok."
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "SID=abc123; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/api/v2/app/version":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"5.3.0"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % server.server_address[1]

    # 5.2+ 的 204
    MODE["value"] = "204"
    client = QbtClient(url, "admin", "pass")
    assert client.login() is True
    assert client.app_version() == "5.3.0"
    print("[OK] 204 No Content 登录成功并可调用 API")

    # 旧版 200 "Ok."
    MODE["value"] = "ok"
    client = QbtClient(url, "admin", "pass")
    assert client.login() is True
    print("[OK] 200 Ok. 登录兼容")

    # 密码错误
    MODE["value"] = "fails"
    client = QbtClient(url, "admin", "wrong")
    try:
        client.login()
        raise AssertionError("错误密码不应登录成功")
    except QbtAuthError as exc:
        assert "密码" in str(exc)
    print("[OK] Fails. 正确识别为密码错误")

    server.shutdown()
    print("\n登录兼容性测试全部通过。")


if __name__ == "__main__":
    main()
