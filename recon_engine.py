"""A Recon-Engine for Penetration Testing.
"""

import threading
import socket
import Queue

from region_trace import TraceRoute
from network_packets.dns_parser import DNSResolver
from ip_address import IPAddress

LOCALHOST = ('localhost', 5555)
MAX_MSG = 1024

class ReconProtocol(object):
    def __init__(self):
        pass

class ReconClient(object):

    def __init__(self):
        self.connect()

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect(LOCALHOST)
        except socket.error, msg:
            raise

    def send(self, message):
        if len(message) > MAX_MSG:
            errmsg = 'message too large: msg-{} > MAX-{}'
            raise Exception(errmsg).format(len(message), MAX_MSG)
        self.sock.sendall(message)

class ReconServer(threading.Thread):
    def __init__(self, shared_queue=None):
        super(ReconServer, self).__init__()

        if isinstance(shared_queue, Queue.Queue):
            self.shared_queue = shared_queue
        else:
            self.shared_queue = Queue.Queue()
        self.alive = threading.Event()
        self.alive.set()
        self.start()

    def connect(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(LOCALHOST)
            sock.listen(1)
        except socket.error, msg:
            self.alive.clear()
            raise
        self.sock = sock

    def run(self):
        try:
            self.connect()
            self.connection, self.client_address = self.sock.accept()
            while self.alive.isSet():
                command = self.connection.recv(MAX_MSG)
                print command
        finally:
            self.connection.close()

class ReconEngine():

    def __init__(self):
        self.tracerotue_queue = Queue.Queue()
        self.dns_queue = Queue.Queue()
        self.dnsr = DNSResolver(shared_queue=self.dns_queue)


    def traceroute(self, ip):
        TraceRoute(ip, shared_queue=self.traceroute_queue)



