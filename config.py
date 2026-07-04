# None for auto-detection, or set manually
TRUSTED_GATEWAY = "None"  # e.g. "192.168.1.1"
TRUSTED_DHCP_SERVER = "None"  # e.g. "192.168.1.1"

INTERFACE = None  # e.g. "\\Device\\NPF_{1E514016-1566-4FDE-888C-281DC2F2883F}" on Windows, "eth0" on Linux
# leave as 'None' for Scapy auto-detection(conf.iface) - not recommended

STARVATION_THRESHOLD = 10
STARVATION_WINDOW = 5
STARVATION_COOLDOWN = 30
