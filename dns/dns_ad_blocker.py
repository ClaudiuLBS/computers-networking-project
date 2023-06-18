import socket


class DNS_AD_BLOCKER:
  def __init__(self, ip = '127.0.0.1', port = 53) -> None:
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    self.sock.bind((ip, port))
    self.ads_list = [item.strip() for item in open('ads.in', 'r').readlines()]


  def get_question_domain(self, data: bytes) -> tuple:
    # dupa primii 12 octetii se termina headerul si incepe sectiune de querries
    data = data[12:] 
    domain_parts = []
    idx = 0
      
    while data[idx] != 0:
      next_idx = idx + data[idx] + 1 # urmatorul byte care reprezinta lungimea unui sir
      current_part = data[idx+1:next_idx].decode('utf-8') # sirul curent din domeniu
      domain_parts.append(current_part)
      idx = next_idx

    # adaugam 1 sa obtinem lungimea sirului, apoi TYPE si CLASS, fiecare cate 2 bytes
    total_length = (idx + 1) + 2 + 2 
    return (domain_parts, total_length)


  def default_record(self) -> bytes:
    OFFSET = b'\xc0\x0c' # primii 2 biti sunt egali cu 1, apoi urmeaza numarul 12 care e dimensiunea headerului => c0 0c
    TYPE = (1).to_bytes(2, 'big') # A = 1
    CLASS = (1).to_bytes(2, 'big') # IN = 1
    TTL = (400).to_bytes(4, 'big') # TTL = 400, pe 4 bytes
    RDLENGTH = (4).to_bytes(2, 'big') # ipv4 => lungime 4 
    RDATA = (0).to_bytes(4, 'big') # IP = 0.0.0.0 deci practic 00 00 00 00 in hexa

    return OFFSET + TYPE + CLASS + TTL + RDLENGTH + RDATA


  def build_response(self, data: bytes) -> bytes:
    ID = data[:2]

    # Setam flagurile QR = 1 si restul 0
    FLAGS = b'\x80\x00'

    # Question Count
    QDCOUNT = (1).to_bytes(2, 'big')

    # Answer Count
    ANCOUNT = (1).to_bytes(2, 'big')
    
    # Nameserver Count
    NSCOUNT = (0).to_bytes(2, 'big')

    # Additional Count
    ARCOUNT = (0).to_bytes(2, 'big')

    # Primii 12 bytes reprezinta headerul
    dns_header = ID + FLAGS + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    # QUERIES
    _, domain_total_length = self.get_question_domain(data)
    dns_question = data[12 : 12 + domain_total_length] # domeniu, type si class

    # ANSWERS
    dns_body = self.default_record()

    return dns_header + dns_question + dns_body


  def run_actual_dns(self, data: bytes):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_server_address = ('8.8.8.8', 53)
    
    try:
      sock.sendto(data, dns_server_address)
      response, _ = sock.recvfrom(65535)
      return response
    
    except socket.timeout:
      print("DNS request timed out")

    finally:
      sock.close()


  def is_good_domain(self, domain_name: str) -> bool:
    for item in self.ads_list:
      if item in domain_name:
        return False
    return True


  def run(self) -> None:
    while True:
      data, addr = self.sock.recvfrom(65535)
      domain_name = '.'.join(self.get_question_domain(data)[0])
      dns_response = self.build_response(data)

      if self.is_good_domain(domain_name):
        print(domain_name)
        dns_response = self.run_actual_dns(data)
        
      try:
        self.sock.sendto(dns_response, addr)

      except socket.timeout:
        print('DNS request time out')



if __name__ == '__main__':
  dns = DNS_AD_BLOCKER()
  dns.run()