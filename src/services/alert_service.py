"""后台告警服务 — 监控 target-mac 入网/离网事件，触发邮件推送。"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Set
import yaml

from .email_sender import send_alert

logger = logging.getLogger(__name__)

_last_alert: dict = {}
_previous_macs: Set[str] = set()
_target_present: bool = False
_just_quit: bool = False

_fastapi_app = None


def _load_config():
    cfg_path = Path(__file__).resolve().parent.parent / "config.yaml"
    with open(cfg_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _get_scan_result():
    """调用 wifi_scout 的扫描逻辑，返回设备列表。"""
    from .wifi_scout import _do_scan, get_local_network, _history
    network = get_local_network()
    if network is None:
        return []
    entries = _do_scan(network, probe=True, tcp=False)
    result = []
    for e in entries:
        mac = e["mac"]
        h = _history.get(mac, {})
        result.append({
            "ip": e["ip"],
            "mac": mac,
            "classification": _classify_wrapper(mac),
            "first_seen": h.get("first_seen"),
        })
    return result


def _classify_wrapper(mac: str) -> str:
    from .wifi_scout import classify_device
    return classify_device(mac)


async def _scan_loop():
    """后台循环：定时扫描 + 检测 target-mac 入网。"""
    config = _load_config()
    target_mac = config.get("target-mac", "").strip().upper()
    from .wifi_scout import _runtime_target
    if _runtime_target:
        target_mac = _runtime_target
    if not target_mac:
        logger.warning("[Alert] target-mac not configured, alert disabled")
        return

    alert_window = config.get("alert", {}).get("alert_window_minutes", 1)
    cooldown_min = config.get("alert", {}).get("cooldown_minutes", 5)
    scan_interval = config.get("alert", {}).get("scan_interval_seconds", 30)

    logger.info(
        f"[Alert] Monitoring target MAC: {target_mac}, "
        f"window={alert_window}min, cooldown={cooldown_min}min, "
        f"interval={scan_interval}s"
    )

    def _send(subject: str, body: str, mac: str, now: datetime):
        try:
            send_alert(subject, body)
            _last_alert[mac] = now
            logger.info(f"[Alert] Email sent: {subject}")
        except Exception as e:
            logger.error(f"[Alert] Failed to send email: {e}")

    def _time_str(dt: datetime) -> str:
        return dt.astimezone(
            timezone(timedelta(hours=8))
        ).strftime("%Y-%m-%d %H:%M:%S")

    global _previous_macs, _target_present, _just_quit

    while True:
        try:
            devices = _get_scan_result()
            now = datetime.now(timezone.utc)
            current_macs = {d["mac"] for d in devices}

            target_found = any(d["mac"] == target_mac for d in devices)

            # --- 入网检测 ---
            if target_found:
                dev = next(d for d in devices if d["mac"] == target_mac)
                first = dev.get("first_seen")
                if first and (now - first).total_seconds() <= alert_window * 60:
                    if _just_quit or _check_cooldown(target_mac, now, cooldown_min):
                        subject = f"[WiFi Alert] {target_mac} device connected"
                        body = (
                            f"{target_mac} device access wifi in "
                            f"{_time_str(first)}\n"
                            f"IP: {dev['ip']}\n"
                            f"Type: {dev['classification']}\n"
                        )
                        _send(subject, body, target_mac, now)
                        _just_quit = False

            # --- 离网检测（不受 cooldown 限制）---
            if _target_present and not target_found:
                subject = f"[WiFi Alert] {target_mac} device quit"
                body = (
                    f"{target_mac} device quit wifi in "
                    f"{_time_str(now)}\n"
                )
                _send(subject, body, target_mac, now)
                _just_quit = True
                # 清理追踪数据，下次接入视为新连接
                from .wifi_scout import _history
                _history.pop(target_mac, None)

            _target_present = target_found
            _previous_macs = current_macs

        except Exception as e:
            logger.error(f"[Alert] Scan loop error: {e}")

        await asyncio.sleep(scan_interval)


def _check_cooldown(mac: str, now: datetime, cooldown_min: int) -> bool:
    if mac not in _last_alert:
        return True
    return (now - _last_alert[mac]).total_seconds() >= cooldown_min * 60


def start_alert_service(app):
    """注册 FastAPI 启动/关闭事件，启动后台告警扫描。"""
    global _fastapi_app
    _fastapi_app = app

    @app.on_event("startup")
    async def _start():
        asyncio.create_task(_scan_loop())
        logger.info("[Alert] Background alert service started")

    @app.on_event("shutdown")
    async def _stop():
        logger.info("[Alert] Background alert service stopped")
