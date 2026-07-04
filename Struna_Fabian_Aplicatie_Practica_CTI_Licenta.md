# TOOL PASIV DE MONITORIZARE DHCP CU DETECȚIE ALE ATACURILOR


# Repo
https://github.com/OnuSike/dhcp-monitor

--------------------------------------------------

# Necesar

- Python 3.10+
- [Npcap](https://npcap.com/#download) (doar pentru Windows)
- Scapy
- Flask

--------------------------------------------------

# Clonare repo

git clone https://github.com/OnuSike/dhcp-monitor
cd dhcp-monitor

--------------------------------------------------

# WINDOWS

# Pași de instalare:
python.exe -m pip install --upgrade pip
pip install scapy flask

# Lansare aplicație:
python .\main.py

--------------------------------------------------

# LINUX

# Pași de instalare:
sudo apt update
sudo apt install -y python3 python3-pip
sudo apt install -y libpcap-dev tcpdump
pip install scapy flask

# Lansare aplicație:
sudo python3 main.py

--------------------------------------------------

# Linux(venv)

# Pași de instalare:
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
sudo apt install -y libpcap-dev tcpdump
pip install scapy flask
sudo python3 -m venv /opt/dhcp-venv
sudo /opt/dhcp-venv/bin/pip install scapy flask

# Lansare aplicație:
sudo /opt/dhcp-venv/bin/python3 main.py

--------------------------------------------------

# config.py

# None for auto-detection, or set manually
TRUSTED_GATEWAY = "None"  # e.g. "192.168.1.1"
TRUSTED_DHCP_SERVER = "None"  # e.g. "192.168.1.1"

INTERFACE = None  # e.g. "\\Device\\NPF_{1E514016-1566-4FDE-888C-281DC2F2883F}" on Windows, "eth0" on Linux
# leave as 'None' for Scapy auto-detection(conf.iface) - not recommended

STARVATION_THRESHOLD = 10
STARVATION_WINDOW = 5
STARVATION_COOLDOWN = 30

--------------------------------------------------

# Server-ul web

http://127.0.0.1:5000