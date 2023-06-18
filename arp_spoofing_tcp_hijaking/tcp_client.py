# TCP client
import socket, logging, time, sys

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)


port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)
try:
    sock.connect(server_address)
    logging.info('Handshake cu %s', str(server_address))
    i = 0
    while True:
        sock.send('Client Message'.encode('utf-8'))
        data = sock.recv(1024)
        logging.info('Content primit: "%s"', data)
        time.sleep(1)
except Exception as e:
    sock.close()
    raise e
