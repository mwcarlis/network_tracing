"""A Recon-Engine for Penetration Testing.
"""

import time
import ast
import threading
import socket
import heapq
import Queue

import filelock
import prettyprint

from region_trace import TraceRoute
from ip_address import IPAddress
from port_scan import PortScanner
from network_packets.dns_parser import DNSResolver


SERVER_LOCKFILE_WAIT = '.recon_server.lock'
SERVER_LOCKFILE_ALIVE = '.recon_server_running.lock'

LOCALHOST = ('localhost', 5555)
MAX_MSG = 10*1024

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
        items = message.split('---')
        if 'cm.echo' in items:
            reply = 'cm.print---{}'.format(items[-1])
            self.iface.sendall(reply)
            return self.iface
        elif 'cm.print' in items:
            print len(items)
            prettyprint.pp(items[1])
            return self.iface
        elif 'cm.stop' in items:
            self.iface.close()
            self.iface = None
            return None

    def parse_server(self, message=''):
        items = message.split('---')
        header = items[0]
        if 'cm.echo' == header:
            reply = 'cm.print---{}'.format(items[-1])
            self.iface.sendall(reply)
            return self.iface
        elif 'cm.print' == header:
            reply = 'cm.stop---{}'.format(items[-1])
            self.iface.sendall(reply)
            self.iface.close()
            self.iface = None
            return self.iface
        elif 'cm.stop' == header:
            reply = 'cm.stop---dummy'
            self.iface.sendall(reply)
            self.iface.close()
            self.iface = None
            return self.iface
        elif 'cm.args' == header:
            # Users passed arguments into the server.
            # Put these arguments in the ReconEngine Queue.

            self.shared_queue.put((self.queue_id, items[-1]))
            self.expected_reply = True
            while self.server_alive.isSet():
                # Expect a reply from ReconEngine for these arguments.
                try:
                    body = self.engine_queue.get(block=True, timeout=2)
                    self.expected_reply = False
                except Queue.Empty:
                    continue
                reply = 'cm.print---{}'.format(body)
                # Once we reply to the client request, stop the communication.
                self.iface.sendall(reply)
                self.iface.close()
                self.iface = None
                break
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
            sock.settimeout(1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, MAX_MSG)
            sock.bind(LOCALHOST)
            sock.listen(1)
        except socket.error, msg:
            self.alive.clear()
            raise
        self.sock = sock

    def _manage_connection(self, wait_flock):
        try:
            with wait_flock.acquire(timeout=2):
                if self.connection is None:
                    self.connection, self.client_address = self.sock.accept()
                    self.protocol.new_iface(self.connection)
                    print 'connected'
            command = self.connection.recv(MAX_MSG)
            self.connection = self.protocol.parse_cmd(command)
        except filelock.Timeout:
            raise
        except socket.timeout:
            # heartbeat to end the thread.
            pass

    def run(self):
        self.connection = None
        server_alive_flock = filelock.FileLock(SERVER_LOCKFILE_ALIVE)
        server_wait_flock = filelock.FileLock(SERVER_LOCKFILE_WAIT)
        try:
            with server_alive_flock.acquire(timeout=0):
                self.connect()
                while self.alive.isSet():
                    self._manage_connection(server_wait_flock)
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
        print 'replen', len(reply)
        print reply
        if self.protocol.expected_reply:
            self.protocol.put_reply(reply)
            return True
        return False

    def get_queue(self):
        return self.shared_queue

class JobMgmt(object):
    def __init__(self, factory, shared_queue, job_limit=0):
        self.factory = factory
        self.shared_queue = shared_queue
        self.pending_qq = []
        self.running_qq = []
        self.record = {}
        self.job_limit = job_limit

    def _clean_jobs(self):
        """Remove dead threads from running_qq
        """
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
        """Queue a job on target.
        """
        if priority and ( target not in self.record ):
            self.pending_qq.insert(0, target)
            self.record[target] = True
        elif target not in self.record:
            self.pending_qq.append(target)
            self.record[target] = True

    def _schedule_job(self):
        """If our job_limit allows, schedule a job.
        """
        jobs_active = len(self.running_qq)
        if jobs_active <= self.job_limit and self.job_limit > 0:
            # We have room in the pool of size job_limit.
            target = self.pending_qq.pop(0)
            thread = self.factory(target, self.shared_queue)
            self.running_qq.append(thread)
            return True
        return False

    def manage_jobs(self):
        """Manage scheduling.
        """
        # Remove the dead jobs
        self._clean_jobs()
        if len(self.pending_qq) > 0:
            # We have jobs pending to schedule
            self._schedule_job()
        return len(self.running_qq)

class DNSCache(object):
    """A dns cache which is very fast to search for records.
    """
    def __init__(self, cache_limit=1000):
        self.dns_cache = {}
        self.cache_limit = cache_limit
        self.CACHE_ID = 'cach_id'
        self.CACHE_RECORD = 'cache_record'
        self.cache_size = 0
        self.cache_total = 0
        self.dns_record_map = {}

    def add_record(self, dns_record):
        """Add a dns record to the dns_cache.
        """
        self.cache_size += 1
        self.cache_total += 1

        # The records id is the total record cnt
        record_id = self.cache_total
        self.dns_record_map[record_id] = dns_record
        for ip in dns_record['ips']:
            self.dns_cache[ip] = record_id
        for domain in dns_record['domain']:
            self.dns_cache[domain] = record_id

    def remove_record(self, dns_record):
        """Remove a record from DNSCache.
        """
        record_ids = []
        for ip in dns_record['ips']:
            # Remove the ip's from cache.
            if ip in self.dns_cache:
                record_ids.append(self.dns_cache.pop(ip))
                self.cache_size -= 1
        for domain in dns_record['domain']:
            # Remove the domain's from cache.
            if domain in self.dns_cache:
                record_ids.append(self.dns_cache.pop(domain))
                self.cache_size -= 1
        for rec_id in record_ids:
            # Remove all record_id's from the dns_records
            if rec_id in self.dns_record_map:
                self.dns_record_map.pop(record_id)

    def is_record(self, dns_record):
        """True if a record exists.
        """
        for key in ['ips', 'domain']:
            for target in dns_record[key]:
                if target in self.dns_cache:
                    return True
        return False

    def _merge_record(self, dns_record):
        """Try to get a record from DNSCache
        """
        ret_record = {
            'ips': [],
            'domain': [],
        }
        for ip in dns_record['ips']:
            # Get the ips that we have for this record.
            if ip not in ret_record['ips']:
                ret_record['ips'].append(ip)
        for domain in dns_record['domain']:
            # Get the domains we have for this record.
            if ip not in ret_record['domain']:
                ret_record['domain'].append(domain)
        return ret_record

    def find_record(self, host_ip):
        if host_ip in self.dns_cache:
            record_id = self.dns_cache[host_ip]
            a_record = self.dns_record_map[record_id]
            return self._merge_record(a_record)


class ReconEngine(threading.Thread):

    def __init__(self):
        super(ReconEngine, self).__init__()

        self.recon_queue = Queue.Queue()

        self.dnsr = DNSResolver(shared_queue=self.recon_queue)
        self.rcs = ReconServer(shared_queue=self.recon_queue)
        self.ipa = IPAddress()

        self.portscan_job = JobMgmt(PortScanner, self.recon_queue, job_limit=4)
        self.traceroute_job = JobMgmt(TraceRoute, self.recon_queue, job_limit=2)
        self.jobs = [self.portscan_job, self.traceroute_job]

        self.alive = threading.Event()
        self.alive.set()
        self.start()

    def _queue_up(self, record):
        """Add record.domain to the wait_queues.
        """
        domain = record['domain_request']
        if not domain:
            return False
        for job_mgr in self.jobs:
            job_mgr.queue_job(target=domain)
        return True

    def manage_user_requests(self, pending_qq):
        pass


    def run(self):
        """This is the master state machine of the ReconEngine.  All of
        the state machine revolves around a Queue protocol from it's many
        producer threads.
        """
        start = time.time()
        pending_queue = {}
        hosts_seen = {}
        knowledge = {}
        user_qq = []
        dns_cache = DNSCache()
        try:
            while self.alive.isSet():
                try:
                    # Always push a tuple (record_type, item)
                    record_type, record = self.recon_queue.get(block=True, timeout=3)

                    if record_type == 'dnsresolve':
                        # TODO For now assume dns is faster than the other jobs.
                        # Could be missing requests associated with other jobs.
                        # We got a dnsresolver item. Queue up some jobs.
                        if dns_cache.is_record(record):
                            return
                        # We don't know about this packet
                        dns_cache.add_record(record)

                    elif record_type == 'traceroute':
                        # We got a traceroute item.
                        domain_req = record['domain_request']
                        knowledge[domain_req][record_type] = record[domain_req]
                        pending_queue[domain_req][record_type] = True

                        # for key, val in record.iteritems():
                        #     print key, val
                        # print '\n\n'
                    elif record_type == 'port_scanner':
                        # We got a port scanner item
                        print 'port_scan',
                        prettyprint.pp(record)
                        domain_req = record['domain_request']
                        knowledge[domain_req][record_type] = record[domain_req]
                        pending_queue[domain_req][record_type] = True

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
                        print 'record', record
                        if not self._queue_up({ 'domain_request': record }):
                            continue
                        knowledge[record] = {}
                        pending_queue[record] = {
                                'port_scanner': False,
                                'traceroute': False,
                                # 'dnsrecord': False,
                        }
                        # self.rcs.reply_user('hello_engine')

                    else:
                        # Leave this here for clarity.
                        pass
                    for req_name, val in pending_queue.iteritems():
                        if val['port_scanner'] and val['traceroute']:
                            dns_rec = dns_cache.find_record(req_name)
                            # pending_queue[req_name]['dnsresolve'] = dns_ec
                            pending_queue[req_name]['dnsresolve'] = dns_rec
                            print 'pp_queue', pending_queue[req_name]
                            self.rcs.reply_user(prettyprint.pp_str(knowledge))



                except Queue.Empty:
                    continue

                finally:
                    delta = time.time()
                    if 5.0 <= (delta - start):
                        # Use a time based heartbeat.
                        print 'heartbeat'
                        start = delta


                # Clean out the finished threads from the queues.
                for job_mgr in self.jobs:
                    job_mgr.manage_jobs()
                self.manage_user_requests(user_qq)
            print 'endofloop',
            #self.rcs.reply_user(prettyprint.pp_str(knowledge))
            prettyprint.pp(knowledge)

        except:
            raise
        finally:
            # Spin down the beast
            # Wait for the child threads to stop.
            # TODO: See if daemon threads are safe.
            self.dnsr.alive.clear()
            self.rcs.alive.clear()

            for job in self.jobs:
                job.pending_qq = []
            stime = time.time()
            cleanup = True
            # Lets spin down the threads.
            while cleanup:
                delta = time.time()
                if delta - stime > 5:
                    print 'dying-beat'
                    stime = delta

                num_done = 0
                for job_mgr in self.jobs:
                    if job_mgr.manage_jobs() == 0:
                        num_done += 1
                time.sleep(0.25)

                try:
                    self.recon_queue.get(block=True, timeout=0.1)
                except Queue.Empty:
                    pass

                self.manage_user_requests(user_qq)
                if num_done >= len(self.jobs):
                    cleanup = False

if __name__ == "__main__":
    import time
    import os, sys
    if not os.geteuid() == 0:
        sys.exit("\nOnly a root user can run this\n")

    try:
        rc = ReconEngine()
        start = time.time()
        time.sleep(60)
    except:
        raise
    finally:
        try:
            rc.alive.clear()
        except NameError:
            pass



