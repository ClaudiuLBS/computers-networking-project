import socket
import sys
import requests
import time
from collections import defaultdict
import pandas as pd
import os

def save_data(ips: set):
    print()
    df = pd.DataFrame({"IP": [], "COUNTRY": [], "REGION": [], "CITY": [], "LATITUDE": [], "LONGITUDE": []})
    for location in ips:
        df = df._append(request_ipinfo(location), ignore_index=True)
    print(df)
    df[~df["IP"].isin(set(pd.read_csv("locations.csv")['IP'].tolist()))].to_csv("locations.csv", mode='a', header=False, index=False)
    pass
        

def request_ipinfo(ip_addr: str):
    response = requests.get(f"http://ip-api.com/json/{ip_addr}")
    data = None
    if response.status_code == 200:
        data: dict = response.json()
        if not (data["status"] == "fail" and data["message"] == "private range"):
            location = [
                data.get('country', ''), 
                data.get('regionName', ''),
                data.get('city', ''),
                data.get('lat', ''),
                data.get('lon', '')
            ]
            return pd.DataFrame({"IP": [ip_addr], "COUNTRY": [location[0]], "REGION": [location[1]], "CITY": [location[2]], "LATITUDE": [location[3]], "LONGITUDE": [location[4]]})
    else:
        print(f"\nError: {response.status_code}")
    


def traceroute(dest_ip: str, port: int = 33434, max_ttl: int = 30, queries: int = 3):
    '''
    dest_ip: goal of the traceroute command

    port: port to which the command sends probes, ranging from 33434 to 33534

    max_ttl: max TTL value to be reached

    queries: number of probes sent at each hop
    '''

    # socket de UDP
    udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    # socket RAW de citire a răspunsurilor ICMP
    icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    # setam timout in cazul in care socketul ICMP la apelul recvfrom nu primeste nimic in buffer
    icmp_recv_socket.settimeout(3)

    ttl = 1
    found_target = False
    ips = set()
    # Stop if we've reached our destination or the max number of hops is achieved
    while not found_target and ttl - 1 != max_ttl:
        addr, prev = None, None
        response_times = []
        queries_response = defaultdict(list)
        print(f"\n{ttl}.", end='')
        for q in range(queries):
            # Set the incremental TTL value for the packet to be sent
            udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            # Send the packet
            t1 = time.time()
            udp_send_sock.sendto(b"salut", (dest_ip, port))
            try:
                # Wait for the ICMP Time Exceeded message
                data, (addr, _) = icmp_recv_socket.recvfrom(63535)
                t2 = time.time()
                # la 20 se termina headerul IP, si primi 2 bytes sunt TYPE si CODE pentru ICMP
                # TYPE 03 = DESTINATION UNREACHABLE | CODE 03 = PORT UNREACHABLE
                if data[20:22].hex() == '0303':
                    found_target = True

                ips.add(addr)
                print(f"\n<{addr}> {(t2 - t1) * 1000.0:.2f}ms" if addr != prev else f" | {(t2 - t1) * 1000.0:.2f}ms", end='')
                prev = addr
            except socket.timeout:
                print(('' if prev == '*' else '\n') + '*', end='')
                prev = '*'
        ttl += 1

    udp_send_sock.close()
    icmp_recv_socket.close()

    save_data(ips)
    
if __name__ == '__main__':
    if (len(sys.argv) != 2):
        raise Exception('traceroute takes exactly one ipv4 address as argument')
    if not os.path.exists("locations.csv"):
        with open("locations.csv", mode='w'):
            pd.DataFrame({"IP": [], "COUNTRY": [], "REGION": [], "CITY": [], "LATITUDE": [], "LONGITUDE": []}).to_csv("locations.csv", mode='a', index=False)
    traceroute(sys.argv[1])
    print()