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

    def __init__(self, proto_side='client',
        shared_queue=None,
        server_alive=None,
        queue_id='user_request'
    ):
        """(shared_queue AND server_alive) -> iff -> proto_side='server'
        """
        self.iface = MockIface()
        if proto_side == 'client':
            # The client is easy
            self.parse_cmd = self.parse_client

        elif proto_side == 'server':
            # The server protocol is aware of the active server.
            self.parse_cmd = self.parse_server
            if not isinstance(shared_queue, Queue.Queue):
                msg = 'shared_queue type, expected: {} got: {}'
                raise ValueError(msg.format('Queue', shared_queue))
            if not server_alive:
                msg = 'server_alive type, expected: {} got: {}'
                raise ValueError(msg.format('threading.Event:', server_alive))
            self.shared_queue=shared_queue
            self.server_alive = server_alive
            self.queue_id = queue_id
            self.engine_queue = Queue.Queue()

    def new_iface(self, iface):
        self.iface = iface

    def put_reply(self, reply):
        self.engine_queue.put(reply)

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
        header = [items[0]]
        if 'cm.echo' == header:
            reply = 'cm.print-{}'.format(items[-1])
            self.iface.sendall(reply)
            return self.iface
        elif 'cm.print' == header:
            print message
            reply = 'cm.stop-{}'.format(items[-1])
            self.iface.sendall(reply)
            self.iface.close()
            self.iface = None
            return self.iface
        elif 'cm.stop' == header:
            reply = 'cm.stop-dummy'
            self.iface.sendall(reply)
            self.iface.close()
            self.iface = None
            return self.iface
        elif 'cm.args' == header:
            # Users passed arguments into the server.
            # Put these arguments in the ReconEngine Queue.
            self.shared_queue.put((self.queue_id, items[-1]))
            while self.server_alive.isSet():
                # Expect a reply from ReconEngine for these arguments.
                try:
                    body = self.engine_queue.get(block=True, timeout=2)
                except Queue.Empty:
                    continue
                reply = 'cm.print-{}'.format(body)
                # Once we reply to the client request, stop the communication.
                self.iface.sendall(reply)
                self.iface.close()
                self.iface = None
            return self.iface


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
        # Tell the Server when to stop being alive.
        self.alive = threading.Event()
        self.queue_id = queue_id

        # The server has a protocol
        self.protocol = ReconProtocol(
            proto_side='server',
            shared_queue=shared_queue,
            server_alive=self.alive
        )
        if isinstance(shared_queue, Queue.Queue):
            self.shared_queue = shared_queue
        else:
            self.shared_queue = Queue.Queue()

        # Set the server alive.
        self.alive.set()
        self.start()

    def connect(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
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

    def reply_user(self, reply):
        if self.protocol.expected_reply:
            self.protocol.put_reply(reply)
            return True
        return False

    def get_queue(self):
        return self.shared_queue

class JobMgmt(object):
    def __init__(self, factory, job_limit=5):
        self.factory = factory
        self.pending_qq = []
        self.running_qq = []
        self.job_limit = job_limit

    def _clean_jobs(self):
        dead_threads = []
        for th in self.running_qq:
            if not th.alive:
                # Get the dead scans
                dead_threads.append(th)
        for th in dead_threads:
            # Remove the dead scans
            index = self.running_qq.index(th)
            self.running_qq.pop(index)

    def queue_job(self, target, priority='false'):
        if priority:
            self.pending_qq.insert(0, target)
        else:
            self.pending_qq.append(target)

    def _schedule_job(self):
        jobs_active = len(self.running_qq)
        if jobs_active <= self.job_limit:
            target = self.pending_qq.pop(0)
            thread = self.factory(target)
            self.running_qq.append(thread)
            return True
        return False

    def manage_jobs(self):
        self._clean_jobs()
        if self.pending_qq > 0:
            self._schedule_job()


class ReconEngine(threading.Thread):

    def __init__(self):
        super(ReconEngine, self).__init__()

        self.recon_queue = Queue.Queue()

        self.dnsr = DNSResolver(shared_queue=self.recon_queue)
        self.rcs = ReconServer(shared_queue=self.recon_queue)
        # self.ipa = IPAddress()

        self.portscans = []
        self.traceroutes = []

        self.alive = threading.Event()
        self.alive.set()
        self.start()

    def _clean_oneshot_threads(self, pool):
        """Remove the dead threads that run as oneshots from running pool.
        """
        dead_threads = []
        for th in pool:
            if not th.alive:
                # Get the dead scans
                dead_threads.append(th)
        for th in dead_threads:
            # Remove the dead scans
            index = pool.index(th)
            pool.pop(index)

    def manage_threads(self, pending_qq, running_qq, obj_factory):
        """Mange running and queued threads of type obj_factory.
        """
        self._clean_oneshot_threads(running_qq)
        num_pending = len(pending_qq)
        if num_pending > 0:
            target = pending_qq[0]
            if self.spin_thread(target, running_qq, obj_factory):
                # There was room in the thread pool.
                pending_qq.pop(0)

    def manage_user_requests(self, user_qq):
        """Manage the user requests from client to ReconServer.
        """
        pass

    def spin_thread(self, target, running_qq, obj_factory):
        """Spin up a thread-target of type-obj_factory & add to running queue.
        """
        MAX_SPINNING = 4
        length = len(running_qq)
        if length <= MAX_SPINNING:
            thread = obj_factory(target, shared_queue=self.recon_queue)
            running_qq.append(thread)
            return True
        return False

    def _queue_up(self, record, wait_queues, record_maps):
        """Add record.domain to the wait_queues and remember in record_maps.
        """
        domain = record['domain_request']
        if not domain:
            return False
        for w_qq, rec_map in zip(wait_queues, record_maps):
            if domain not in rec_map:
                w_qq.append(domain)
                rec_map[domain] = True
        return True

    def run(self):
        start = time.time()
        tracert_qq = []
        portscan_qq = []
        wait_queues = (tracert_qq, portscan_qq)
        user_qq = []
        record_maps = ({}, {})
        try:
            while self.alive.isSet():
                try:
                    # Always push a tuple (record_type, item)
                    record_type, record = self.recon_queue.get(block=True, timeout=3)

                    if record_type == 'dnsresolve':
                        # We got a dnsresolver item. Queue up some jobs.
                        if not self._queue_up(record, wait_queues, record_maps):
                            continue
                    elif record_type == 'traceroute':
                        # We got a traceroute item.
                        for key, val in record.iteritems():
                            print key, val
                        print '\n\n'
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
                    elif record_type == 'user_request':
                        # The queue will receive user requests.
                        # TODO LATER.
                        # user_qq.append(request)
                        pass

                except Queue.Empty:
                    continue

                finally:
                    delta = time.time()
                    if 5.0 <= (delta - start):
                        # Use a time based heartbeat.
                        print 'heartbeat'
                        start = delta

                # Clean out the finished threads from the queues.
                self.manage_threads(tracert_qq, self.traceroutes, TraceRoute)
                self.manage_threads(portscan_qq, self.portscans, PortScanner)
                self.manage_user_requests(user_qq)

        except:
            raise
        finally:
            # Spin down the beast
            # Wait for the child threads to stop.
            # TODO: See if daemon threads are safe.
            self.dnsr.alive.clear()
            self.rcs.alive.clear()

            tracert_qq = []
            portscan_qq = []
            stime = time.time()
            # Lets spin down the threads.
            while len(self.portscans) > 0 and len(self.traceroutes) > 0:
                if time.time() - stime > 5:
                    print '\n\n'
                    print self.traceroutes
                    print self.portscans
                    stime = time.time()

                self.manage_threads(tracert_qq, self.traceroutes, TraceRoute)
                self.manage_threads(portscan_qq, self.portscans, PortScanner)
                self.manage_user_requests(user_qq)
                try:
                    self.recon_queue.get(block=True, timeout=0.1)
                except Queue.Empty:
                    continue

if __name__ == "__main__":
    import time
    import os, sys
    if not os.geteuid() == 0:
        sys.exit("\nOnly a root user can run this\n")

    rc = ReconEngine()
    start = time.time()
    try:
        time.sleep(60)
    except:
        if rc.alive.isSet():
            rc.alive.clear()
        raise
    finally:
        rc.alive.clear()



