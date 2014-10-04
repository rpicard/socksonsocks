from socksonsocks import put_socks_on
import socket
from ssl import wrap_socket


def main():
    s = socket.socket()
    s = put_socks_on(s, '127.0.0.1', 5555, '50.18.192.251', 443)
    ss = wrap_socket(s)
    ss.sendall('GET /?q=ip HTTP/1.1\r\nHost: duckduckgo.com\r\n\r\n')
    print ss.recv(8192)

    ss.close()
    

if __name__ == '__main__':
    main()
