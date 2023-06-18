# TCP Server
import socket, logging, time

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)

sock.bind(server_address)
sock.listen(5)

logging.info("Serverul a pornit pe %s si portul %d", adresa, port)

while True:
    logging.info('Asteptam conexiui...')
    conexiune, address = sock.accept()
    logging.info("Handshake cu %s", address)
    
    try:
        while True:
            recv_data = conexiune.recv(1024)
            logging.info('Content primit: "%s"', recv_data)
            
            conexiune.send('Server message'.encode('utf-8'))
    except Exception as e:
        print(e)
        conexiune.close()
        sock.close()
