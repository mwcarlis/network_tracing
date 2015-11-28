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

def assign_none(blob):
    blob = None


class ReconProtocol(object):
    # Protocol argument flags.
    ARG_NONE    = 0
    ARG_IFACE   = 1
    ARG_PAYLOAD = 2
    ARG_MESSAGE = 3

    def __init__(self, proto_side='client'):
        self.iface = MockIface()
        SERVER_CMDS = {
            'stop': (
                (self.ARG_NONE, self.iface.close),
                (self.ARG_IFACE, assign_none),
            ),
            'echo': (
                (self.ARG_PAYLOAD, self.iface.sendall),
            ),
        }
        CLIENT_CMDS = {
            'stop': (
                (self.ARG_NONE, self.iface.close),
                (self.ARG_IFACE, assign_none),
            ),
            'echo': (
                (self.ARG_PAYLOAD, self.iface.sendall),
            ),
            'send_recv': (
                (self.ARG_MESSAGE, self.iface.sendall),
                (self.ARG_MESSAGE, self.iface.recv),
            ),
        }
        if proto_side == 'client':
            self.proto_cmds = CLIENT_CMDS
        elif proto_side == 'server':
            self.proto_cmds = SERVER_CMDS

    def new_iface(self, iface):
        print 'setting new iface'
        self.iface = iface

    def parse_cmd(self, message=''):
        # Parse the message into a cmd, and a payload.
        try:
            cmd, payload = tuple(message.split('-'))
            # Get the command sequence for this cmd.
            cmd_sequence = self.proto_cmds[cmd]
            # Take appropriate action for this command.
            for arg, runnable_cmd in cmd_sequence:
                if arg == self.ARG_NONE:
                    runnable_cmd()
                elif arg == self.ARG_IFACE:
                    runnable_cmd(self.iface)
                elif arg == self.ARG_PAYLOAD:
                    runnable_cmd(message)
                elif arg == self.ARG_MESSAGE:
                    runnable_cmd(message)
                else:
                    print 'cmd_error:', message
        except KeyError:
            print 'proto_error:', message



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
        self.sock.sendall(message)
        ret_msg = self.sock.recv(MAX_MSG)
        self.protocol.parse_cmd(ret_msg)

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



