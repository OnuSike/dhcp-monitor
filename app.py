from flask import Flask, jsonify, render_template
import sqlite3
from datetime import datetime
import ipaddress

app = Flask(__name__)
DB_PATH = "leases.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/leases")
def get_leases():
    conn = get_db()
    leases = conn.execute("SELECT * FROM leases ORDER BY ip").fetchall()
    conn.close()
    return jsonify([dict(l) for l in leases])

@app.route("/api/pool")
def get_pool():
    conn = get_db()
    leases_rows = conn.execute("SELECT ip, mac, hostname, expiry, suspicious FROM leases").fetchall()
    subnets_rows = conn.execute("SELECT network FROM subnets").fetchall()
    conn.close()

    if not subnets_rows:
        return jsonify([])

    leased_map = {}
    for row in leases_rows:
        leased_map[row["ip"]] = {
            "mac": row["mac"],
            "hostname": row["hostname"],
            "expiry": row["expiry"],
            "suspicious": row["suspicious"]
        }

    result = []
    for subnet_row in subnets_rows:
        network = ipaddress.ip_network(subnet_row["network"])
        all_ips = []
        for ip in network.hosts():
            ip_str = str(ip)
            lease = leased_map.get(ip_str)
            all_ips.append({
                "ip": ip_str,
                "leased": lease is not None,
                "mac": lease["mac"] if lease else None,
                "hostname": lease["hostname"] if lease else None,
                "expiry": lease["expiry"] if lease else None,
                "suspicious": lease["suspicious"] if lease else 0
            })
        result.append({"network": subnet_row["network"], "ips": all_ips})

    return jsonify(result)

@app.route("/api/alerts")
def get_alerts():
    conn = get_db()
    alerts = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50").fetchall()
    conn.close()
    return jsonify([dict(a) for a in alerts])

if __name__ == "__main__":
    app.run(debug=True, port=5000)