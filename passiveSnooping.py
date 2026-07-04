from scapy.all import sniff, DHCP, BOOTP, Ether, IP
from datetime import datetime, timedelta
import sqlite3
import threading
import ipaddress
from detect import init_alerts_db, check_rogue_server, check_starvation, check_spoofing
from detect import trusted_dhcp_server, trusted_gateway
from config import INTERFACE

DB_PATH = "leases.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS leases (
        ip TEXT PRIMARY KEY,
        mac TEXT,
        hostname TEXT,
        expiry TEXT,
        last_seen TEXT,
        suspicious INTEGER DEFAULT 0
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS subnets (
    network TEXT PRIMARY KEY,
    first_seen TEXT
    )''')
    
    conn.commit()
    conn.close()

    init_alerts_db()

def save_lease(ip, mac, hostname, lease_time, suspicious=0):
    expiry = datetime.now() + timedelta(seconds=lease_time)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO leases (ip, mac, hostname, expiry, last_seen, suspicious)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (ip, mac, hostname, expiry.strftime("%Y-%m-%d %H:%M:%S"),
               datetime.now().strftime("%Y-%m-%d %H:%M:%S"), suspicious))
    network = str(ipaddress.ip_network(f"{ip}/24", strict=False))
    c.execute('''INSERT OR IGNORE INTO subnets (network, first_seen) VALUES (?, ?)''',
              (network, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    print(f"[+] Lease: {ip} → {mac} | expires {expiry.strftime('%H:%M:%S')} {'[SUSPICIOUS]' if suspicious else ''}")

def remove_lease(ip):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM leases WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()
    print(f"[-] Released: {ip}")

def handle_packet(pkt):
    if not pkt.haslayer(DHCP):
        return

    dhcp_options = {}
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and len(opt) == 2:
            dhcp_options[opt[0]] = opt[1]

    msg_type = dhcp_options.get("message-type")

    if msg_type == 5:  # ACK
        server_ip = pkt[IP].src
        if server_ip == trusted_dhcp_server:
            ip = pkt[BOOTP].yiaddr
            mac = pkt[Ether].dst
            hostname = dhcp_options.get("hostname", b"").decode(errors="ignore")
            lease_time = dhcp_options.get("lease_time", 86400)
            offered_gateway = dhcp_options.get("router")
            is_suspicious = 0
            if offered_gateway and offered_gateway != trusted_gateway:
                is_suspicious = 1
            if ip and ip != "0.0.0.0":
                save_lease(ip, mac, hostname, lease_time, suspicious=is_suspicious)

    elif msg_type == 7:  # RELEASE
        ip = pkt[BOOTP].ciaddr
        if ip and ip != "0.0.0.0":
            remove_lease(ip)

    # check attacks
    if msg_type in (2, 5):   # OFFER or ACK - server responses | check rogue dhcp server
        server_ip = pkt[IP].src
        server_mac = pkt[Ether].src
        check_rogue_server(server_ip, server_mac)

    if msg_type == 1:   # DISCOVER | check starvation attack
        check_starvation(pkt[Ether].src)

    if msg_type == 5:   # ACK | check dhcp spoofing
        offered_gateway = dhcp_options.get("router")
        if offered_gateway:
            check_spoofing(pkt[IP].src, offered_gateway)

def start_capture():
    iface = INTERFACE
    print("[*] Starting DHCP capture...")
    sniff(iface=iface, filter="udp port 67 or udp port 68", prn=handle_packet, store=0)

def start_in_thread():
    t = threading.Thread(target=start_capture, daemon=True)
    t.start()

if __name__ == "__main__":
    init_db()
    start_capture()