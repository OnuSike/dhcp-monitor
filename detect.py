from datetime import datetime
import sqlite3
from collections import defaultdict
import time

DB_PATH = "leases.db"

from config import (TRUSTED_GATEWAY, TRUSTED_DHCP_SERVER,
                    STARVATION_THRESHOLD, STARVATION_WINDOW, STARVATION_COOLDOWN)

trusted_gateway = TRUSTED_GATEWAY
trusted_dhcp_server = TRUSTED_DHCP_SERVER

def init_alerts_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        attack_type TEXT,
        description TEXT,
        source_ip TEXT,
        source_mac TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS dhcp_servers (
        ip TEXT PRIMARY KEY,
        mac TEXT,
        first_seen TEXT,
        trusted INTEGER DEFAULT 0
    )''')
    conn.commit()
    conn.close()

def save_alert(attack_type, description, source_ip=None, source_mac=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO alerts (timestamp, attack_type, description, source_ip, source_mac)
                 VALUES (?, ?, ?, ?, ?)''',
              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), attack_type, description, source_ip, source_mac))
    conn.commit()
    conn.close()
    print(f"[ALERT] {attack_type}: {description}")

# Rogue
def check_rogue_server(server_ip, server_mac):
    global trusted_dhcp_server
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    if trusted_dhcp_server is None:
        # auto-detect first seen server
        trusted_dhcp_server = server_ip
        c.execute('''INSERT OR IGNORE INTO dhcp_servers (ip, mac, first_seen, trusted)
                     VALUES (?, ?, ?, 1)''',
                  (server_ip, server_mac, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
        print(f"[*] Trusted DHCP server registered: {server_ip} ({server_mac})")
        return

    if server_ip != trusted_dhcp_server:
        conn.close()
        save_alert(
            "ROGUE DHCP SERVER",
            f"Unknown DHCP server detected at {server_ip} ({server_mac})",
            source_ip=server_ip,
            source_mac=server_mac
        )
        return
    
    conn.close()


# Starvation
discover_tracker = defaultdict(list)

last_starvation_alert = 0

def check_starvation(src_mac):
    global last_starvation_alert
    now = time.time()
    
    discover_tracker[src_mac].append(now)
    discover_tracker[src_mac] = [t for t in discover_tracker[src_mac] if now - t < STARVATION_WINDOW]
    
    active_macs = [mac for mac, times in discover_tracker.items() if len(times) > 0]
    
    if len(active_macs) >= STARVATION_THRESHOLD:
        if now - last_starvation_alert > STARVATION_COOLDOWN:
            save_alert(
                "DHCP STARVATION",
                f"High rate of DISCOVER packets from {len(active_macs)} different MACs in {STARVATION_WINDOW}s window",
                source_mac=src_mac
            )
            last_starvation_alert = now
            discover_tracker.clear()


# Spoofing
trusted_gateway = TRUSTED_GATEWAY

def check_spoofing(server_ip, offered_gateway):
    global trusted_gateway
    
    # first ACK from trusted server, record the gateway
    if trusted_gateway is None:
        trusted_gateway = offered_gateway
        print(f"[*] Trusted gateway registered: {trusted_gateway}")
        return
    
    # if gateway changed, alert
    if offered_gateway != trusted_gateway:
        save_alert(
            "DHCP SPOOFING",
            f"ACK from {server_ip} offering suspicious gateway {offered_gateway} (expected {trusted_gateway})",
            source_ip=server_ip
        )