"""命令行入口。"""

from __future__ import annotations

import argparse
import csv
import logging
import logging.handlers
import os
import sys
import time

from .config import Config
from .engine import Engine
from .qbt import QbtError

DEFAULT_CONFIG = "config.json"

def _banned_entries(prefs):
    """qB 的 banned_IPs 是换行分隔字符串；兼容个别返回数组的版本。"""
    raw = prefs.get("banned_IPs") or ""
    if isinstance(raw, str):
        return [x for x in raw.split("\n") if x]
    return [str(x) for x in raw]



def setup_logging(cfg: Config, verbose: bool = False):
    level = getattr(logging, str(cfg.get("logging.level", "INFO")).upper(), logging.INFO)
    if verbose:
        level = logging.DEBUG
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")
    if cfg.get("logging.console", True):
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        root.addHandler(sh)

    log_file = cfg.get("logging.file")
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=int(cfg.get("logging.max_bytes", 10485760)),
            backupCount=int(cfg.get("logging.backups", 5)),
            encoding="utf-8",
        )
        fh.setFormatter(fmt)
        root.addHandler(fh)


def load(args) -> Config:
    path = args.config or os.environ.get("QBT_ANTILEECH_CONFIG", DEFAULT_CONFIG)
    cfg = Config.load(path)
    setup_logging(cfg, getattr(args, "verbose", False))
    return cfg


def cmd_run(args) -> int:
    cfg = load(args)
    engine = Engine(cfg, dry_run=(True if args.dry_run else None))
    engine.run_forever(once=args.once)
    return 0


def cmd_status(args) -> int:
    cfg = load(args)
    path = cfg.status_path
    if not os.path.isfile(path):
        print("暂无运行状态（尚未执行过 run）")
        return 1
    import json
    with open(path, "r", encoding="utf-8") as fh:
        print(json.dumps(json.load(fh), ensure_ascii=False, indent=2))
    return 0


def cmd_bans(args) -> int:
    cfg = load(args)
    engine = Engine(cfg)
    bans = engine.store.active_bans()
    if not bans:
        print("当前没有生效的封禁")
        return 0
    now = time.time()
    print("%-40s %8s %10s  %s" % ("IP", "分数", "剩余", "原因"))
    for b in bans[: args.limit]:
        left = "永久" if b.expires <= 0 else "%dm" % max(0, (b.expires - now) // 60)
        print("%-40s %8.1f %10s  %s" % (b.ip, b.score, left, b.reason[:70]))
    print("\n共 %d 条生效封禁" % len(bans))
    return 0


def cmd_ban(args) -> int:
    cfg = load(args)
    engine = Engine(cfg)
    ok = engine.manual_ban(args.ip, args.reason or "manual", args.hours)
    return 0 if ok else 2


def cmd_unban(args) -> int:
    cfg = load(args)
    engine = Engine(cfg)
    if args.all:
        bans = engine.store.active_bans()
        for b in bans:
            engine.manual_unban(b.ip, sync=False)
        engine.ensure_blocklist(force=True)
        print("已解除 %d 条封禁" % len(bans))
        return 0
    if not args.ip:
        print("请指定 IP，或使用 --all")
        return 2
    ok = engine.manual_unban(args.ip)
    return 0 if ok else 1


def cmd_doctor(args) -> int:
    cfg = load(args)
    engine = Engine(cfg)
    print("配置文件 : %s" % cfg.path)
    print("数据目录 : %s" % cfg.data_dir)
    print("WebUI    : %s" % cfg.get("qbt.base_url"))

    try:
        engine.qbt.login()
    except QbtError as exc:
        print("登录      : 失败 - %s" % exc)
        return 1
    auth_mode = "API Key" if engine.qbt.api_key else "用户名/密码"
    print("登录      : OK（%s）" % auth_mode)

    try:
        print("版本      : %s" % engine.qbt.app_version())
    except QbtError as exc:
        print("版本      : 读取失败 - %s" % exc)
        return 1

    # 以下均为可选诊断项，单项失败不影响整体结论
    try:
        info = engine.qbt.transfer_info()
        print("连接状态  : %s" % info.get("connection_status"))
    except QbtError as exc:
        print("连接状态  : 读取失败 - %s" % exc)

    print("封禁方式  : %s" % engine.blocklist_mode)
    try:
        prefs = engine.qbt.preferences()
        if engine.manual is not None:
            entries = _banned_entries(prefs)
            print("手动屏蔽  : %d 条（IP过滤 → 手动屏蔽IP地址）" % len(entries))
        if engine.use_file:
            print("IP过滤器  : enabled=%s path=%s" % (prefs.get("ip_filter_enabled"),
                                                      prefs.get("ip_filter_path")))
    except QbtError as exc:
        print("封禁名单  : 读取失败 - %s" % exc)

    print("白名单    : allow_private=%s cidrs=%s" % (
        engine.allow_private, cfg.get("whitelist.cidrs")))
    if engine.use_file:
        print("过滤器文件: %s (exists=%s)" % (engine.filter.path, os.path.isfile(engine.filter.path)))
        print("重载方式  : %s" % engine.filter.reload_mode)
    print("生效封禁  : %d" % engine.store.count_active_bans())
    print("防火墙层  : %s" % ("启用" if engine.fw.enabled else "关闭"))
    print("\n自检通过：可以执行 run --dry-run 观察一轮。")
    return 0


def cmd_blocklist(args) -> int:
    """查看当前封禁方式与 qB 侧条目数量。"""
    cfg = load(args)
    engine = Engine(cfg)
    print("封禁方式 : %s" % engine.blocklist_mode)
    print("本地记录 : %d 条生效封禁" % engine.store.count_active_bans())
    if engine.manual is not None:
        try:
            engine.qbt.login()
            entries = _banned_entries(engine.qbt.preferences())
            print("手动屏蔽 : %d 条（qB 当前）" % len(entries))
            for ip in entries[: args.limit]:
                print("  - %s" % ip)
            if len(entries) > args.limit:
                print("  ... 其余 %d 条" % (len(entries) - args.limit))
        except QbtError as exc:
            print("手动屏蔽 : 读取失败 - %s" % exc)
            return 1
    if engine.use_file:
        print("过滤器文件: %s (exists=%s)" % (engine.filter.path, os.path.isfile(engine.filter.path)))
    return 0


def cmd_sync_blocklist(args) -> int:
    """立即把当前封禁同步到 qB（手动屏蔽列表 / 文件过滤器）。"""
    cfg = load(args)
    engine = Engine(cfg)
    try:
        engine.qbt.login()
    except QbtError as exc:
        print("登录失败: %s" % exc)
        return 1

    bans = sorted(engine.store.active_ban_ips())
    engine._blocklist_dirty = True
    engine.ensure_blocklist(force=True)

    ok = True
    if engine.manual is not None:
        ok = bool(engine.manual.last_ok)
        print("手动屏蔽列表: %d 条 %s" % (
            engine.manual.last_count, "（已写入 qB）" if ok else "（写入失败）"))
    if engine.use_file:
        ok = bool(engine._last_reload_ok) and ok
        print("IP 过滤器   : %s（%s）" % (
            engine.filter.path, "已重载" if engine._last_reload_ok else "重载失败"))
    print("生效封禁    : %d 条" % len(bans))
    if ok:
        engine.store.record_event("-", "sync", "手工同步封禁名单", "%d 条" % len(bans))
        print("同步完成。")
    else:
        print("同步失败：请检查 WebUI 账号是否有修改设置权限。")
    return 0 if ok else 1


def cmd_reload_filter(args) -> int:
    """兼容旧命令：manual 模式同步手动屏蔽列表，file 模式强制重载文件。"""
    if args is not None:
        print("提示：reload-filter 已并入 sync-blocklist，后续可直接使用该命令。")
    return cmd_sync_blocklist(args)


def cmd_export(args) -> int:
    cfg = load(args)
    engine = Engine(cfg)
    out = args.output or os.path.join(cfg.data_dir, "bans-export.csv")
    with open(out, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ip", "score", "created", "expires", "active", "reason"])
        for b in engine.store.active_bans():
            writer.writerow([b.ip, b.score,
                             time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(b.created)),
                             "never" if b.expires <= 0 else
                             time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(b.expires)),
                             b.active, b.reason])
    print("已导出: %s" % out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="antileech",
        description="qBittorrent 自动反吸血系统（WebUI API v2）",
    )
    p.add_argument("--config", "-c", default=None, help="配置文件路径，默认 ./config.json")
    p.add_argument("--verbose", "-v", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="启动守护循环")
    r.add_argument("--once", action="store_true", help="只跑一个周期（配合计划任务）")
    r.add_argument("--dry-run", action="store_true", help="只记录不实际封禁")
    r.set_defaults(func=cmd_run)

    s = sub.add_parser("status", help="查看运行状态")
    s.set_defaults(func=cmd_status)

    b = sub.add_parser("bans", help="列出当前封禁")
    b.add_argument("--limit", type=int, default=50)
    b.set_defaults(func=cmd_bans)

    mb = sub.add_parser("ban", help="手工封禁")
    mb.add_argument("ip")
    mb.add_argument("--reason", default="manual")
    mb.add_argument("--hours", type=int, default=24, help="0 表示永久")
    mb.set_defaults(func=cmd_ban)

    ub = sub.add_parser("unban", help="解除封禁（误封恢复）")
    ub.add_argument("ip", nargs="?")
    ub.add_argument("--all", action="store_true")
    ub.set_defaults(func=cmd_unban)

    d = sub.add_parser("doctor", help="连通性与配置自检")
    d.set_defaults(func=cmd_doctor)

    bl = sub.add_parser("blocklist", help="查看当前封禁方式与 qB 侧条目")
    bl.add_argument("--limit", type=int, default=30)
    bl.set_defaults(func=cmd_blocklist)

    sb = sub.add_parser("sync-blocklist", help="立即把封禁名单同步到 qB")
    sb.set_defaults(func=cmd_sync_blocklist)

    rf = sub.add_parser("reload-filter", help="[兼容] 等同 sync-blocklist")
    rf.set_defaults(func=cmd_reload_filter)

    e = sub.add_parser("export", help="导出封禁列表 CSV")
    e.add_argument("--output", "-o", default=None)
    e.set_defaults(func=cmd_export)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except FileNotFoundError as exc:
        print("错误: %s" % exc)
        return 2
    except KeyboardInterrupt:
        print("已停止")
        return 0
