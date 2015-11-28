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

class MockIface(object):
    def __init__(self):
        pass
    def close(self):
        raise Exception('Mock Close')
    def sendall(self, msg):
        raise Exception('Mock Sendall')
    def recv(self, num):
        raise Exception('Mock Recv')


class ReconProtocol(object):
    # Protocol argument flags.
    ARG_NONE    = 0
    ARG_IFACE   = 1
    ARG_PAYLOAD = 2
    ARG_MESSAGE = 3
    ARG_RECV    = 4

    def __init__(self, proto_side='client'):
        self.iface = MockIface()
        if proto_side == 'client':
            self.parse_cmd = self.parse_client
        elif proto_side == 'server':
            self.parse_cmd = self.parse_server

    def new_iface(self, iface):
        self.iface = iface

    def parse_client(self, message=''):
        items = message.split('-')
        if 'cm.echo' in items:
            reply = 'cm.print-{}'.format(items[-1:])
            self.iface.sendall(reply)
        elif 'cm.print' in items:
            print message
        elif 'cm.stop' in items:
            self.iface.close()
            self.iface = None

    def parse_server(self, message=''):
        items = message.split('-')
        if 'cm.echo' in items:
            reply = 'cm.print-{}'.format(items[-1:])
            self.iface.sendall(reply)
        elif 'cm.print' in items:
            print message
            reply = 'cm.stop-{}'.format(items[-1:])
            self.iface.sendall(reply)
        elif 'cm.stop' in items:
            reply = 'cm.stop-dummy'
            self.iface.sendall(reply)
            self.iface.close()
            self.iface = None


class ReconClient(object):

    def __init__(self):
        self.protocol = ReconProtocol(proto_side='client')
        self.connect()

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect(LOCALHOST)
        except socket.error, msg:
            raise
        self.protocol.new_iface(self.sock)

    def send(self, message):
        if len(message) > MAX_MSG:
            errmsg = 'message too large: msg-{} > MAX-{}'
            raise Exception(errmsg).format(len(message), MAX_MSG)
        # Send a message.
        self.sock.sendall(message)
        # Receive a response and parse it.
        self.protocol.parse_cmd(self.sock.recv(MAX_MSG))

class ReconServer(threading.Thread):
    def __init__(self, shared_queue=None):
        super(ReconServer, self).__init__()
        self.protocol = ReconProtocol(proto_side='server')

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
        self.connection = None
        try:
            self.connect()
            while self.alive.isSet():
                if self.connection is None:
                    print 'blocking connect'
                    self.connection, self.client_address = self.sock.accept()
                    self.protocol.new_iface(self.connection)
                command = self.connection.recv(MAX_MSG)
                self.protocol.parse_cmd(command)
        except:
            raise
            #self.connection.close()

class ReconEngine():

    def __init__(self):
        self.tracerotue_queue = Queue.Queue()
        self.dns_queue = Queue.Queue()
        self.dnsr = DNSResolver(shared_queue=self.dns_queue)


    def traceroute(self, ip):
        TraceRoute(ip, shared_queue=self.traceroute_queue)



