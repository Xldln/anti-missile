"""
WiFi 设备扫描 API — FastAPI Router。

GET  /api/devices   扫描局域网设备，返回 MAC / IP / 类型 / 存活时长
GET  /api/target    获取当前追踪的 target-mac
POST /api/target    设置运行时 target-mac（不写入 config.yaml）
"""

import sys
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional, List, Dict

from fastapi import APIRouter, Query, Body
from pydantic import BaseModel
import ipaddress

# 运行时 target-mac（优先于 config.yaml）
_runtime_target: Optional[str] = None

# 导入 scripts/ 下的扫描核心函数
_scripts = Path(__file__).resolve().parent.parent.parent / "scripts"
sys.path.insert(0, str(_scripts))
from search_mac_inwlan import (       # noqa: E402
    get_local_network, ping_sweep, get_arp_table,
    filter_entries, translate_type, classify_device,
    get_wifi_station_count, get_router_model,
    mdns_probe, ssdp_probe, udp_broadcast_poke,
)

router = APIRouter(prefix="/api", tags=["WiFi Scout"])

# 内存级追踪：每个 MAC 首次/最近被观测时间
_history: Dict[str, dict] = defaultdict(dict)


def _track(mac: str):
    """记录本次扫描时间，保留首次出现时间。"""
    now = datetime.now(timezone.utc)
    entry = _history[mac]
    if "first_seen" not in entry:
        entry["first_seen"] = now
    entry["last_seen"] = now
    entry["seen_count"] = entry.get("seen_count", 0) + 1


def _do_scan(network: str, probe: bool = True, tcp: bool = False):
    """执行完整扫描流程，返回过滤后的设备列表。"""
    ping_sweep(network)
    if tcp:
        from search_mac_inwlan import tcp_probe
        all_hosts = [str(h) for h in ipaddress.IPv4Network(
            network, strict=False).hosts()]
        tcp_probe(all_hosts, ports=[80, 443], timeout_sec=0.3)
    if probe:
        mdns_probe()
        ssdp_probe()
        udp_broadcast_poke(network)
    entries = get_arp_table()
    return filter_entries(entries, network)


# ---------- Pydantic Models ----------

class DeviceInfo(BaseModel):
    ip: str
    mac: str
    type: str
    classification: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    duration_seconds: Optional[float] = None
    seen_count: int = 0


class ScanResponse(BaseModel):
    timestamp: str
    network: str
    router: Optional[str] = None
    wifi_stations: Optional[int] = None
    device_count: int
    target_mac: Optional[str] = None
    devices: List[DeviceInfo]


class TargetRequest(BaseModel):
    mac: str


# ---------- Endpoints ----------

@router.get("/devices", response_model=ScanResponse)
def get_devices(
    probe: bool = Query(True, description="Enable mDNS/SSDP discovery"),
    tcp: bool = Query(False, description="Enable TCP port scan"),
):
    now = datetime.now(timezone.utc)
    network = get_local_network()
    if network is None:
        return ScanResponse(
            timestamp=now.isoformat(),
            network="unknown",
            device_count=0,
            devices=[],
        )

    entries = _do_scan(network, probe=probe, tcp=tcp)
    sta_count = get_wifi_station_count()
    router_model = get_router_model()

    devices: List[DeviceInfo] = []
    for e in entries:
        mac = e["mac"]
        _track(mac)
        h = _history[mac]
        dur = None
        if h.get("first_seen"):
            dur = round((now - h["first_seen"]).total_seconds(), 1)
        devices.append(DeviceInfo(
            ip=e["ip"],
            mac=mac,
            type=translate_type(e["type"]),
            classification=classify_device(mac),
            first_seen=h["first_seen"].isoformat(),
            last_seen=h["last_seen"].isoformat(),
            duration_seconds=dur,
            seen_count=h.get("seen_count", 1),
        ))

    return ScanResponse(
        timestamp=now.isoformat(),
        network=network,
        router=router_model,
        wifi_stations=sta_count,
        device_count=len(devices),
        target_mac=_effective_target(),
        devices=devices,
    )


def _effective_target() -> Optional[str]:
    if _runtime_target:
        return _runtime_target
    cfg_path = Path(__file__).resolve().parent.parent / "config.yaml"
    try:
        import yaml
        with open(cfg_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        return config.get("target-mac", "").strip().upper() or None
    except Exception:
        return None


@router.get("/target")
def get_target():
    return {"target_mac": _effective_target()}


@router.post("/target")
def set_target(body: TargetRequest):
    global _runtime_target
    _runtime_target = body.mac.strip().upper() if body.mac.strip() else None
    return {"target_mac": _runtime_target, "status": "ok"}
