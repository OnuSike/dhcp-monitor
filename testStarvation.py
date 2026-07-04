from scapy.all import *
import random

iface = '\\Device\\NPF_{1E514016-1566-4FDE-888C-281DC2F2883F}'

for i in range(15):
    mac = f"aa:bb:cc:dd:ee:{i:02x}"
    pkt = (Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') /
           IP(src='0.0.0.0', dst='255.255.255.255') /
           UDP(sport=68, dport=67) /
           BOOTP(chaddr=bytes.fromhex(mac.replace(':', ''))) /
           DHCP(options=[('message-type', 'discover'), 'end']))
    sendp(pkt, iface=iface)

print("Sent 15 DISCOVER packets from different MACs")