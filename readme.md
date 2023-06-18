## Traceroute

```bash
  cd ./traceroute
  python3 traceroute.py
```

## Ad-Blocker DNS
Put ad server domains in the file 'ads.in'
```bash
  nano /etc/resolf.conf
  # change nameserver to 127.0.0.1
  cd ./dns
  python3 dns_ad_blocker.py
```

## ARP Spoofing
```bash
  cd ./arp_spoofing_tcp_hijaking
  python3 arp_spoofing.py <target_ip> <default_gateway>
```

## TCP Hijaking
```bash
  docker compose up -d
```
```bash
  # server
  docker compose exec server bash
  cd ./elocal/arp_spoofing_tcp_hijaking
  python3 tcp_server.py  
```
```bash
  # client
  docker compose exec client bash
  cd ./elocal/arp_spoofing_tcp_hijaking
  python3 tcp_client.py  
```
```bash
  # middle
  docker compose exec middle bash
  cd ./elocal/arp_spoofing_tcp_hijaking
  python3 arp_spoofing.py 198.7.0.2 198.7.0.1 &
  python3 tcp_hijaking.py 198.7.0.2 198.7.0.1
```
