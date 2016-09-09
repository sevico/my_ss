#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import socketserver
import struct
import string
import select
import codecs
import socket
import hashlib
import functools
import os
import json
import logging
import getopt

try:
    import gevent, gevent.monkey

    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
except ImportError:
    gevent = None
    print >> sys.stderr, 'warning: gevent not found, using threading instead'


def get_table(key):
    m = hashlib.md5()
    m.update(key.encode("utf-8"))
    s = m.digest()
    (a,b) = struct.unpack("<QQ",s)
    table = [chr(c) for (c) in (bytearray.maketrans(b'',b''))]

    for i in range(1,1024):
        table.sort(key=functools.cmp_to_key(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))) #根据 a，b打乱顺序字符表
    return table

def send_all(sock,data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r<0:
            return r
        bytes_sent+=r
        if bytes_sent==len(data):
            return bytes_sent




class ThreadingTCPServer(socketserver.ThreadingMixIn,socketserver.TCPServer):
    allow_reuse_address = True

class Socks5Server(socketserver.StreamRequestHandler):
    def decrypt(self, data):
        return data.translate(decrypt_table)
    def encrypt(self, data):
        return data.translate(encrypt_table)
    def handle_tcp(self,sock,remote):
        try:
            fdest = [sock,remote]
            while True:
                r,w,e = select.select(fdest,[],[])
                if sock in r:
                    data = sock.recv(4096)
                    if len(data)<=0:
                        break
                    result = send_all(remote,self.decrypt(data))
                    if result < len(data):
                        raise Exception('failed to send all data')
                if remote in r:
                    data = remote.recv(4096)
                    if len(data)<=0:
                        break
                    result = send_all(sock,self.encrypt(data))
                    if result<len(data):
                        raise Exception('failed to send all data')
        finally:
            sock.close()
            remote.close()


    def handle(self):
        try:
            sock = self.connection
            addrtype = ord(self.decrypt(self.rfile.read(1)))
            if addrtype ==1:
                addr = socket.inet_ntoa(self.decrypt(self.rfile.read(4)))
            elif addrtype ==3:
                addr = self.decrypt(self.rfile.read(ord(self.decrypt(sock.recv(1)))))
            else:
                logging.warn("addr_type not support")
                return
            port = struct.unpack(">H",self.decrypt(self.rfile.read(2)))
            try:
                logging.info("connecting %s:%d"%(addr,port[0]))
                remote = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
                remote.connect((addr,port[0]))
            except socket.errno as e:
                logging.warn(e)
                return
            self.handle(sock,remote)
        except socket.error as e:
            logging.warn(e)





if __name__ == '__main__':
    reader = codecs.getreader("utf-8")
    os.chdir(os.path.dirname(__file__) or ".")
    print("My ss")
    with open("config.json", "rb") as f:
        config = json.load(reader(f))

    SERVER = config['server']
    PORT = config['server_port']
    KEY = config['password']
    optlist, args = getopt.getopt(sys.argv[1:], 'p:k:')
    for key, value in optlist:
        if key == '-p':
            PORT = int(value)
        elif key == '-k':
            KEY = value
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
    tmp_table=get_table(KEY)
    encrypt_table = ''.join(tmp_table)
    tmp_table = (bytes(list(map(lambda x:ord(x),encrypt_table))))
    decrypt_table = bytearray.maketrans(tmp_table, bytearray.maketrans(b'', b''))
    if '-6' in sys.argv[1:]:
        ThreadingTCPServer.address_family = socket.AF_INET6
    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error  as e:
        logging.error(e)

