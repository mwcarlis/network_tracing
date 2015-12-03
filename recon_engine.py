"""A Recon-Engine for Penetration Testing.
"""

import time
import threading
import socket
import Queue
from region_trace import TraceRoute
from network_packets.dns_parser import DNSResolver
from ip_address import IPAddress
from port_scan import PortScanner
import prettyprint

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
            reply = 'cm.print-{}'.format(items[-1])
            self.iface.sendall(reply)
            return self.iface
        elif 'cm.print' in items:
            print message
            return self.iface
        elif 'cm.stop' in items:
            self.iface.close()
            self.iface = None
            return None

    def parse_server(self, message=''):
        items = message.split('-')
        if 'cm.echo' in items:
            reply = 'cm.print-{}'.format(items[-1])
            self.iface.sendall(reply)
            return self.iface
        elif 'cm.print' in items:
            print message
            reply = 'cm.stop-{}'.format(items[-1])
            self.iface.sendall(reply)
            self.iface.close()
            self.iface = None
            return None
        elif 'cm.stop' in items:
            reply = 'cm.stop-dummy'
            self.iface.sendall(reply)
            self.iface.close()
            self.iface = None
            return None


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
        if self.sock is None:
            self.connect()
        # Send a message.
        self.sock.sendall(message)
        # Receive a response and parse it.
        self.sock = self.protocol.parse_cmd(self.sock.recv(MAX_MSG))

class ReconServer(threading.Thread):
    def __init__(self, shared_queue=None, queue_id='recon_server'):
        super(ReconServer, self).__init__()
        self.queue_id = queue_id
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
            sock.settimeout(5)
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
                try:
                    if self.connection is None:
                        self.connection, self.client_address = self.sock.accept()
                        self.protocol.new_iface(self.connection)
                    command = self.connection.recv(MAX_MSG)
                    self.connection = self.protocol.parse_cmd(command)
                except socket.timeout:
                    # heartbeat to end the thread.
                    pass
        except:
            raise
        finally:
            try:
                self.connection.close()
            except:
                pass
            try:
                self.sock.close()
            except:
                pass

class ReconEngine(threading.Thread):

    def __init__(self):
        super(ReconEngine, self).__init__()

        self.recon_queue = Queue.Queue()

        self.dnsr = DNSResolver(shared_queue=self.recon_queue)
        self.rcs = ReconServer()
        #self.ipa = IPAddress()

        self.portscans = []
        self.traceroutes = []

        self.alive = threading.Event()
        self.alive.set()
        self.start()

    def _clean_oneshot_threads(self, pool):
        dead_threads = []
        for th in pool:
            if not th.alive:
                # Get the dead scans
                dead_threads.append(th)
        for th in dead_threads:
            # Remove the dead scans
            index = pool.index(th)
            pool.pop(index)

    def manage_portscans(self, pending_queue):
        self._clean_oneshot_threads(self.portscans)
        if len(pending_queue) > 0:
            ip = pending_queue[0]
            if self.portscan(ip):
                # There was room in the thread pool.
                pending_queue.pop(0)

    def manage_traceroutes(self, pending_queue):
        self._clean_oneshot_threads(self.traceroutes)
        if len(pending_queue) > 0:
            ip = pending_queue[0]
            if self.traceroute(ip):
                # There was room in the thread pool.
                pending_queue.pop(0)

    def traceroute(self, ip):
        if len(self.traceroutes) <= 5:
            troute = TraceRoute(ip, shared_queue=self.recon_queue)
            self.traceroutes.append(troute)
            return True
        return False

    def portscan(self, ip):
        if len(self.portscans) <= 5:
            pscan = PortScanner(ip, shared_queue=self.recon_queue)
            self.portscans.append(pscan)
            return True
        return False


    def run(self):
        start = time.time()
        records = {}
        inquiry_queue = []
        tracert_qq = []
        portscan_qq = []
        fip = None
        try:
            while self.alive.isSet():
                try:
                    # Always push a tuple (record_type, item)
                    record_type, record = self.recon_queue.get(block=True, timeout=3)

                    if record_type == 'dnsresolve':
                        # We got a dnsresolver item.
                        fip = sorted(record['ips'])[0]
                        if fip not in records:
                            records[fip] = record
                            tracert_qq.append(fip)
                            portscan_qq.append(fip)
                    elif record_type == 'traceroute':
                        # We got a traceroute item.
                        for key, val in record.iteritems():
                            print key, val
                    elif record_type == 'port_scanner':
                        # We got a port scanner item
                        prettyprint.pp(record)
                    elif record_type == 'recon_server':
                        # We got a recon server item
                        pass
                    elif record_type == 'packet_sniffer':
                        # We got a packet sniffer item
                        # TODO LATER.
                        pass

                except Queue.Empty:
                    continue

                # Clean out the finished threads from the queues.
                self.manage_portscans(portscan_qq)
                self.manage_traceroutes(tracert_qq)

                delta = time.time()
                if 5.0 <= (delta - start):
                    # Use a time based heartbeat.
                    print 'heartbeat'
                    start = delta
        except:
            raise
        finally:
            self.dnsr.alive.clear()
            self.rcs.alive.clear()


if __name__ == "__main__":
    import time
    import os, sys
    if not os.geteuid() == 0:
        sys.exit("\nOnly a root user can run this\n")

    rc = ReconEngine()
    time.sleep(60)
    rc.alive.clear()



