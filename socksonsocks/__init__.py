"""
socksonsocks
~~~~~~~~~~~~

This module will (attempt to) help you connect a socket to a SOCKS proxy.

I tried to make this as simple as possible. There is only one function, no
classes or other abstractions.

(c) 2014 by Robert Picard. MIT licensed.

"""

import socket
import struct

def put_socks_on(s, proxy_host, proxy_port, host, port):
    """Connects a socket to a SOCKS proxy and connect that proxy to a host.

    :param s: a socket, as in the result of socket.socket()
    :param proxy_host: an IP address (string) that points to your SOCKS proxy
    :param proxy_port: the port number (int) that your proxy is listening on
    :param host: the IP address (string) of the server you're connecting to
    :param port: the port number (int) on that server

    Running *put_socks_on* is kind of like running socket.connect(). It
    isn't some sort of drop-in replacement yet though.

    Right now it only supports SOCKS 5 (and not really all of it). No
    authentication yet. The code is documented with excerpts from RFC 1928
    if you want to see how it works.

    :todo: Make it a drop-in replacement for `socket.connect()`.

    :todo: Support the full SOCKS 5 RFC (and maybe SOCKS 4).

    Using a SOCKS proxy to connect via SSL. Note how we are still able to
    wrap the socket with ssl:

        >>> import socket
        >>> from ssl import wrap_socket
        >>> from socksonsocks import put_socks_on
        >>> s = put_socks_on(socket.socket(), '127.0.0.1', 5555, '107.21.1.80', 443)
        >>> ss = wrap_socket(s)
        >>> ss.sendall('GET /?q=ip&format=json HTTP/1.1\\r\\n\Host: duckduckgo.com\\r\\n\\r\\n')
        >>> print ss.recv(4096)


    """

    # connect to the SOCKS proxy
    s.connect((proxy_host, proxy_port))

    #   The client connects to the server, and sends a version
    #   identifier/method selection message:
    #
    #                   +----+----------+----------+
    #                   |VER | NMETHODS | METHODS  |
    #                   +----+----------+----------+
    #                   | 1  |    1     | 1 to 255 |
    #                   +----+----------+----------+

    s.send(b'\x05\x01\x00')

    #   The server selects from one of the methods given in METHODS, and
    #   sends a METHOD selection message:
    #
    #                         +----+--------+
    #                         |VER | METHOD |
    #                         +----+--------+
    #                         | 1  |   1    |
    #                         +----+--------+

    res = s.recv(2)

    #   If the selected METHOD is X'FF', none of the methods listed by the
    #   client are acceptable, and the client MUST close the connection.

    if res[1] == b'\xFF':
        print 'NO ACCEPTABLE METHODS'
        s.close()
        return
    elif res[1] != b'\x00':
        print "WRONG METHOD RETURNED BY SERVER"
        s.close()
        return
    elif res[0] != b'\x05':
        print "WRONG VERSION RETURNED BY SERVER"
        s.close()
        return

    #   The SOCKS request is formed as follows:
    #
    #        +----+-----+-------+------+----------+----------+
    #        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    #        +----+-----+-------+------+----------+----------+
    #        | 1  |  1  | X'00' |  1   | Variable |    2     |
    #        +----+-----+-------+------+----------+----------+
    #
    #     Where:
    #
    #          o  VER    protocol version: X'05'
    #          o  CMD
    #             o  CONNECT X'01'
    #             o  BIND X'02'
    #             o  UDP ASSOCIATE X'03'
    #          o  RSV    RESERVED
    #          o  ATYP   address type of following address
    #             o  IP V4 address: X'01'
    #             o  DOMAINNAME: X'03'
    #             o  IP V6 address: X'04'
    #          o  DST.ADDR       desired destination address
    #          o  DST.PORT desired destination port in network octet
    #             order

    req = b'\x05\x01\x00\x01'
    req += ''.join([ chr(int(st)) for st in host.split('.')])
    req += struct.pack('>H', port)

    s.send(req)

    #   The SOCKS request information is sent by the client as soon as it has
    #   established a connection to the SOCKS server, and completed the
    #   authentication negotiations.  The server evaluates the request, and
    #   returns a reply formed as follows:
    #
    #        +----+-----+-------+------+----------+----------+
    #        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    #        +----+-----+-------+------+----------+----------+
    #        | 1  |  1  | X'00' |  1   | Variable |    2     |
    #        +----+-----+-------+------+----------+----------+
    #
    #     Where:
    #
    #          o  VER    protocol version: X'05'
    #          o  REP    Reply field:
    #             o  X'00' succeeded
    #             o  X'01' general SOCKS server failure
    #             o  X'02' connection not allowed by ruleset
    #             o  X'03' Network unreachable
    #             o  X'04' Host unreachable
    #             o  X'05' Connection refused
    #             o  X'06' TTL expired
    #             o  X'07' Command not supported
    #             o  X'08' Address type not supported
    #             o  X'09' to X'FF' unassigned
    #          o  RSV    RESERVED
    #          o  ATYP   address type of following address
    #             o  IP V4 address: X'01'
    #             o  DOMAINNAME: X'03'
    #             o  IP V6 address: X'04'
    #          o  BND.ADDR       server bound address
    #          o  BND.PORT       server bound port in network octet order

    res = s.recv(10)

    if res[1] != b'\x00':
        print "REQUEST FAILED"
        s.close()
        return 

    return s

