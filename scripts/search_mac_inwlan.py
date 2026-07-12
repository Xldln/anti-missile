"""
输出当前 WiFi / 局域网中所有已连接设备的 MAC 地址。
原理：ICMP ping sweep + TCP 端口探测 → 刷新 ARP 表 → 解析 arp -a。
"""

import re
import subprocess
import socket
import ipaddress
import argparse
from typing import Optional, List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

TRY_NOHANG = getattr(socket, "TCP_NOTSENT_LOWAT", None) is not None

OUI_MAP = {
    # Phones
    "00-1E-C2": "Apple",     "64-B9-E8": "Apple",     "F0-18-98": "Apple",
    "9C-30-5B": "Honor",     "28-6C-07": "Huawei",    "00-E0-4C": "Huawei",
    "A0-93-47": "Xiaomi",    "64-64-4B": "Xiaomi",    "F4-B8-5E": "Xiaomi",
    "98-9C-57": "OPPO",      "88-1E-5A": "OnePlus",   "38-87-D5": "Samsung",
    "8C-85-C1": "Samsung",   "CC-05-77": "Samsung",   "BC-9F-EF": "Samsung",
    "00-1A-11": "Google",    "3C-5A-B4": "Google",    "58-CB-52": "Google",
    "C4-93-13": "vivo",      "20-89-86": "vivo",      "34-2F-6D": "Realme",
    "08-00-46": "Sony",
    # Laptops / PCs
    "54-54-52": "Lenovo",    "14-13-17": "Dell",      "18-26-49": "Dell",
    "00-25-9C": "Intel",     "20-16-D8": "Intel",
    # Routers / Networking
    "F4-93-9F": "TP-Link",   "50-C7-BF": "TP-Link",   "30-C6-D7": "H3C",
    "C8-3A-35": "Tenda",     "00-19-15": "Ubiquiti",  "D4-D7-48": "Cisco",
    "DC-A6-32": "RaspberryPi", "B8-27-EB": "RaspberryPi",
    # Gaming / IoT / NAS
    "70-B3-D5": "Amazon",    "A4-77-33": "Amazon",
    "00-08-9B": "Netgear",   "00-14-6C": "Netgear",
    "00-11-32": "Synology",  "00-12-4B": "QNAP",
}


def is_local_mac(mac: str) -> bool:
    """MAC 第2个hex的bit1=1表示本地管理地址(随机/虚拟MAC)。"""
    try:
        first_byte = int(mac[:2], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False


def classify_device(mac: str) -> str:
    """根据 MAC 地址推断设备类型: vendor + type hint。"""
    prefix = mac[:8]
    vendor = OUI_MAP.get(prefix)
    local = is_local_mac(mac)

    parts = []
    if vendor:
        parts.append(vendor)
    if local:
        parts.append("[randomized]")
    else:
        parts.append("[hardware]")
    return " ".join(parts) if parts else "-"


def get_local_network() -> Optional[str]:
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        parts = ip.split(".")
        parts[-1] = "0"
        return ".".join(parts) + "/24"
    except Exception:
        return None


def flags():
    return subprocess.CREATE_NO_WINDOW \
        if hasattr(subprocess, "CREATE_NO_WINDOW") else 0


# ---------- ICMP ----------

def ping_sweep(network: str, timeout_ms: int = 200,
               max_workers: int = 32):
    net = ipaddress.IPv4Network(network, strict=False)
    hosts = list(net.hosts())
    total = len(hosts)
    print(f"[*] ICMP ping sweep {network} "
          f"({total} hosts, {max_workers}t, {timeout_ms}ms) ...",
          end="", flush=True)

    done = 0
    f = flags()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                subprocess.run,
                ["ping", "-n", "1", "-w", str(timeout_ms), str(h)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=f,
            ): h for h in hosts
        }
        for fut in as_completed(futures):
            done += 1
            if done % 32 == 0 or done == total:
                print(f"\r[*] ICMP ping sweep {network} ... {done}/{total}",
                      end="", flush=True)
            _ = fut.result()
    print(f"\r[*] ICMP ping sweep {network} ... done ({done}/{total})     ")


# ---------- TCP ----------

def tcp_probe(hosts: List[str], ports: List[int] = None,
              timeout_sec: float = 0.5, max_workers: int = 64):
    if ports is None:
        ports = [80, 443, 5353, 8080]
    print(f"[*] TCP probe {len(hosts)} hosts on ports {ports} "
          f"({max_workers}t, {timeout_sec}s) ...",
          end="", flush=True)

    responded = set()
    done = 0
    total_attempts = len(hosts) * len(ports)

    def _probe(ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_sec)
        try:
            s.connect((ip, port))
            s.close()
            return ip
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {}
        for ip in hosts:
            for port in ports:
                futures[pool.submit(_probe, ip, port)] = (ip, port)
        for fut in as_completed(futures):
            done += 1
            if done % 128 == 0 or done == total_attempts:
                print(f"\r[*] TCP probe ... {done}/{total_attempts}",
                      end="", flush=True)
            result = fut.result()
            if result:
                responded.add(result)
    print(f"\r[*] TCP probe ... done ({done}/{total_attempts}), "
          f"{len(responded)} hosts responded   ")
    return responded


# ---------- Discovery ----------

MDNS_MULTICAST = ("224.0.0.251", 5353)
SSDP_MULTICAST = ("239.255.255.250", 1900)


def mdns_probe():
    """发送 mDNS 查询，手机/Apple 设备会响应 -> ARP 表刷新。"""
    print("[*] mDNS discovery probe ... ", end="", flush=True)
    query = (
        b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(1)
        sock.sendto(query, MDNS_MULTICAST)
        try:
            sock.recvfrom(1024)
        except socket.timeout:
            pass
        sock.close()
        print("sent")
    except Exception as e:
        print(f"failed ({e})")


def ssdp_probe():
    """发送 SSDP M-SEARCH，安卓/iOS/智能设备会响应。"""
    print("[*] SSDP discovery probe ... ", end="", flush=True)
    query = (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\n'
        b"MX: 2\r\n"
        b"ST: ssdp:all\r\n"
        b"\r\n"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(query, SSDP_MULTICAST)
        try:
            sock.recvfrom(1024)
        except socket.timeout:
            pass
        sock.close()
        print("sent")
    except Exception as e:
        print(f"failed ({e})")


def udp_broadcast_poke(network: str):
    """向子网广播地址发 UDP 包，强制设备 ARP 回应。"""
    net = ipaddress.IPv4Network(network, strict=False)
    broadcast = str(net.broadcast_address)
    print(f"[*] UDP broadcast poke {broadcast}:12345 ... ", end="", flush=True)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(0.5)
        for _ in range(3):
            sock.sendto(b"HELLO", (broadcast, 12345))
        sock.close()
        print("sent (x3)")
    except Exception as e:
        print(f"failed ({e})")

def get_arp_table() -> List[Dict[str, str]]:
    result = subprocess.run(
        ["arp", "-a"],
        capture_output=True, text=True,
        creationflags=flags(),
    )
    entries = []
    for line in result.stdout.splitlines():
        pat = r"\s*(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F\-]{17})\s+(\S+)"
        m = re.match(pat, line)
        if m:
            entries.append({
                "ip": m.group(1),
                "mac": m.group(2).upper(),
                "type": m.group(3),
            })
    return entries


def is_local(ip_str: str, network: str) -> bool:
    try:
        return ipaddress.IPv4Address(ip_str) in ipaddress.IPv4Network(
            network, strict=False)
    except Exception:
        return False


def translate_type(raw: str) -> str:
    tmap = {"动态": "dynamic", "静态": "static"}
    return tmap.get(raw, raw)


def get_oui(mac: str) -> str:
    return OUI_MAP.get(mac[:8], "-")


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "-"


# ---------- main ----------

def get_wifi_station_count() -> Optional[int]:
    """从 netsh wlan 输出中提取当前 BSS 连接的电台数。"""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, encoding="utf-8",
            creationflags=flags(),
        )
        for line in result.stdout.splitlines():
            m = re.search(r"\u8fde\u63a5\u7684\u7535\u53f0:\s*(\d+)", line)
            if m:
                return int(m.group(1))
    except Exception:
        pass
    return None


def get_router_model() -> Optional[str]:
    """尝试访问路由器首页，提取型号。"""
    try:
        import urllib.request
        req = urllib.request.Request("http://192.168.124.1/")
        req.add_header("User-Agent", "Mozilla/5.0")
        resp = urllib.request.urlopen(req, timeout=2)
        html = resp.read().decode("gbk", errors="replace")
        m = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
        if m:
            title = m.group(1)
            title = re.sub(r"&[a-z]+;?", " ", title)
            title = re.sub(r"[^\x20-\x7EA-Za-z0-9 ]", "", title).strip()
            return title
    except Exception:
        pass
    return None


def filter_entries(entries: List[Dict], network: str) -> List[Dict]:
    seen_macs: Set[str] = set()
    filtered = []
    for e in entries:
        mac = e["mac"]
        if mac in seen_macs:
            continue
        if mac.startswith("01-") or mac == "FF-FF-FF-FF-FF-FF":
            continue
        if not is_local(e["ip"], network):
            continue
        seen_macs.add(mac)
        filtered.append(e)
    return filtered


def print_table(entries: List[Dict]):
    if not entries:
        print("[-] No devices found")
        return
    print(f"\n[+] Found {len(entries)} device(s):\n")
    print("{:<16} {:<20} {:<8} {}".format(
        "IP", "MAC", "Type", "Classification"))
    print("-" * 85)
    for e in entries:
        print("{:<16} {:<20} {:<8} {}".format(
            e["ip"], e["mac"], translate_type(e["type"]),
            classify_device(e["mac"])))


def main():
    parser = argparse.ArgumentParser(
        description="Scan all devices on current WiFi/LAN")
    parser.add_argument("--no-tcp", action="store_true",
                        help="Skip TCP port probing")
    parser.add_argument("--tcp-ports", default="80,443,5353,8080",
                        help="TCP ports to probe (default: 80,443,5353,8080)")
    parser.add_argument("--timeout", type=int, default=200,
                        help="ICMP timeout in ms (default: 200)")
    parser.add_argument("--tcp-timeout", type=float, default=0.5,
                        help="TCP timeout in seconds (default: 0.5)")
    args = parser.parse_args()

    network = get_local_network()
    if network is None:
        print("[!] Cannot detect local network")
        return

    net = ipaddress.IPv4Network(network, strict=False)
    all_hosts = [str(h) for h in net.hosts()]

    # Step 1: ICMP ping sweep
    ping_sweep(network, timeout_ms=args.timeout)

    # Step 2: TCP probe for hosts that may block ICMP
    if not args.no_tcp:
        try:
            tcp_ports = [int(p.strip()) for p in args.tcp_ports.split(",")]
        except ValueError:
            tcp_ports = [80, 443]
        tcp_probe(all_hosts, ports=tcp_ports, timeout_sec=args.tcp_timeout)

    # Step 3: Discovery probes (mDNS + SSDP + UDP broadcast)
    mdns_probe()
    ssdp_probe()
    udp_broadcast_poke(network)

    # Step 4: Parse ARP table
    entries = get_arp_table()
    filtered = filter_entries(entries, network)
    print_table(filtered)

    # Extra: WiFi station count from BSS load
    sta_count = get_wifi_station_count()
    if sta_count is not None:
        print(f"\n[*] WiFi BSS reports {sta_count} connected station(s) "
              f"(including this PC)")

    # Router model
    router = get_router_model()
    if router:
        print(f"[*] Router: {router}")

    # Hint
    other_wifi = (sta_count or 1) - 1
    if other_wifi > 0:
        print(f"\n[!] BSS shows {other_wifi} other WiFi client(s), "
              f"but ARP sees only {len(filtered)} total devices.")
        print("    Router likely has AP/client isolation"
              " -- cannot see other WiFi MACs.")
        print("    Log into http://192.168.124.1/ to view full device list.")
    else:
        print("\n[!] Phone not showing? Wake it & open a web page, "
              "then re-run.")


if __name__ == "__main__":
    main()


# my apple phone 7E-4D-86-F1-6D-87