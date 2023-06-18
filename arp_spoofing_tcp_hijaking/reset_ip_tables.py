import os

os.system(f'iptables -D FORWARD -j ACCEPT')
os.system(f'iptables -t nat -s 192.168.68.0/24 -D POSTROUTING -j MASQUERADE')
os.system(f'iptables -t nat -D POSTROUTING -j MASQUERADE')
os.system(f'iptables -D OUTPUT -j ACCEPT')