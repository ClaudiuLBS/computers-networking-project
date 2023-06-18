
class CustomPacket:
  def __init__(self, payload: bytes) -> None:
    self.payload = payload
    self.ip_header = payload[:20]
    self.tcp_end = 20 + self.get_header_length()
    self.tcp_header = payload[20:self.tcp_end]
    self.data = payload[self.tcp_end:]

  def _set_payload(self, payload: bytes) -> None:
    # Every time we update the payload, we update the headers and checksums
    self.payload = payload
    self.ip_header = payload[:20]
    self.tcp_header = payload[20:self.tcp_end]
    self.data = payload[self.tcp_end:]

    self.calculate_tcp_checksum()
    self.calculate_ip_checksum()

  # def check_for_http()

  def get_protocol_type(self):
    return self.ip_header[9]

  def get_source_ip(self) -> str:
    return '.'.join([str(int(x)) for x in self.payload[12:16]])

  def get_dest_ip(self) -> str:
    return '.'.join([str(int(x)) for x in self.payload[16:20]])

  def get_source_port(self) -> int:
    return int.from_bytes(self.tcp_header[:2], 'big')
  
  def get_dest_port(self) -> int:
    return int.from_bytes(self.tcp_header[2:4], 'big')
  
  def get_window(self) -> int:
    return int.from_bytes(self.tcp_header[14:16], 'big')
  
  def get_checksum(self) -> int:
    return int.from_bytes(self.tcp_header[16:18], 'big')
  
  def get_urgent_pointer(self) -> int:
    return int.from_bytes(self.tcp_header[18:20], 'big')
  
  def get_options(self) -> bytes:
    return self.tcp_header[20:]

  # SEQ
  def get_seq(self) -> int:
    return int.from_bytes(self.tcp_header[4:8], 'big')
  
  def set_seq(self, value: int) -> None:
    self._set_payload(self.payload[:24] + value.to_bytes(4, 'big') + self.payload[28:])

  # ACK
  def get_ack(self) -> int:
    return int.from_bytes(self.tcp_header[8:12], 'big')
  
  def set_ack(self, value: int) -> None:
    self._set_payload(self.payload[:28] + value.to_bytes(4, 'big') + self.payload[32:])

  def get_header_length(self) -> int:
    length = self.payload[32] >> 4
    return length * 4


  def get_flags(self, flag: str = None):
    flags =self.tcp_header[13]

    res = {}
    res['FIN'] = flags & 1 != 0
    res['SYN'] = flags & 2 != 0
    res['RST'] = flags & 4 != 0
    res['PSH'] = flags & 8 != 0
    res['ACK'] = flags & 16 != 0
    res['URG'] = flags & 32 != 0
    
    if flag is None:
      return res
    
    return res[flag]
  

  def calculate_ip_checksum(self) -> None:
    data = self.ip_header[:10] + (0).to_bytes(2, 'big') + self.ip_header[12:]
    
    # Divide the header into 16-bit words
    words = [int.from_bytes(data[i:i+2], byteorder='big') for i in range(0, len(data), 2)]

    # Sum all the 16-bit words
    checksum = sum(words)

    # Perform one's complement addition
    while checksum >> 16:
      checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # Take the one's complement of the final sum
    checksum = (~checksum) & 0xFFFF

    self.payload = self.payload[:10] + checksum.to_bytes(2, 'big') + self.payload[12:]
  

  def calculate_tcp_checksum(self) -> None:
    # PSEUDO HEADER + TCP HEADER
    data = (
      self.payload[12:20] # source and dest ip
      + (0).to_bytes(1, 'big') # reserved
      + (6).to_bytes(1, 'big') # tcp protocol
      + len(self.payload[20:]).to_bytes(2, 'big') # tcp length
      + self.payload[20:36] + (0).to_bytes(2, 'big') + self.payload[38:] # tcp header + data
    )
    
    if len(data) % 2 != 0:
      data += b'\x00'
    sum = 0
    for i in range(0, len(data), 2):
      sum += (data[i] << 8) + data[i + 1]

    sum = (sum >> 16) + (sum & 0xFFFF)
    sum += (sum >> 16)

    checksum = (~sum & 0xFFFF).to_bytes(2, 'big')
    self.payload = self.payload[:36] + checksum + self.payload[38:]


  def get_data(self) -> str:
    return self.data.decode('utf-8')

  def set_data(self, data: str) -> None:
    encoded_data = data.encode('utf-8')
    self._set_payload(self.payload[:self.tcp_end] + encoded_data)

    # recalculate the length
    total_length = len(self.payload).to_bytes(2, 'big')
    self._set_payload(self.payload[:2] + total_length + self.payload[4:])
    # the checksums will be calculated automaticaly in _set_payload()