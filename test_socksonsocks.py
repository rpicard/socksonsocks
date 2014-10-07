from socksonsocks import put_socks_on
from ssl import wrap_socket
import socket


def main():
    s = socket.socket()
    s = put_socks_on(s, '127.0.0.1', 5555, '50.18.192.251', 443)
    ss = wrap_socket(s,ciphers='EXPORT')
    ss.do_handshake()

    ss.close()
    

if __name__ == '__main__':
    main()
