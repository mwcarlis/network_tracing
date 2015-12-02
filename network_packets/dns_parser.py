import re
import shlex
import subprocess
import threading
import Queue

class DNSResolver(threading.Thread):

    def __init__(self, shared_queue=None):
        super(DNSResolver, self).__init__()

        if isinstance(shared_queue, Queue.Queue):
            self.shared_queue = shared_queue
        else:
            self.shared_queue = Queue.Queue()
        self.command = 'tshark -f "udp port 53" -Y "dns.qry.type == A"'
        self.pending_requests = {}
        self.alive = threading.Event()
        self.alive.set()
        self.start()

    def run(self):
        pobj = subprocess.Popen(
            shlex.split(self.command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        try:
            lines_iter = iter(pobj.stdout.readline, b"")
            for line in lines_iter:
                line = line.strip()
                row = re.findall(r'[^\s\t]+', line)
                if 'response' in row:
                    self.response_processor(row)
                else:
                    self.query_processor(row)
                if not self.alive.isSet():
                    break
        except:
            raise
        finally:
            self.alive.clear()

    def query_processor(self, row):
        start = 0
        valid = False
        items = {'domain':[], 'request_id': None}
        for val in row:
            if 'query' in val:
                start = 1
                # Just before the DNS request id.
                continue
            elif start == 1:
                # This is the DNS request id
                items['request_id'] = val
                start += 1
                continue
            elif 'A' in val:
                # This comes before a Domain name.
                valid = True
                start = 3
                continue
            if start == 3:
                # This is a Domain name.
                items['domain'].append(val)
                continue
            else:
                # Everything else.
                continue
        if valid:
            # Rember this packet for the response.
            self.pending_requests[items['request_id']] = items
        else:
            # print '\n\nmalfunction\n\n'
            pass

    def response_processor(self, row):
        start = 0
        valid = False
        items = {'domain': [], 'ips': [], 'request_id': None}
        for val in row:
            if 'response' in val:
                # Just before the DNS request ID
                start = 1
                continue
            elif start == 1:
                # This is the DNS request ID
                items['request_id'] = val
                start += 1
                continue
            elif 'CNAME' in val:
                # This comes before a Domain name.
                valid = True
                start = 3
                continue
            elif start == 3:
                # This is a Domain name.
                items['domain'].append(val)
                start += 1
                continue
            elif start > 3 and not 'A' in val:
                # This is an IP for these Domain names.
                items['ips'].append(val)
                start += 1
                continue
            else:
                # Everything else.
                continue
        if valid:
            # Find the packet we remembered for the query
            if items['request_id'] in self.pending_requests:
                request = self.pending_requests.pop(items['request_id'])
                for domain in request['domain']:
                    items['domain'].append(domain)
                self.shared_queue.put(items)
        else:
            # print '\n\n failed_dang'
            # print items
            pass

    def get_queue(self):
        return self.shared_queue


def test_dns_resolver():
    import time

    qq = Queue.Queue()
    dnsr = DNSResolver(shared_queue=qq)
    start = time.time()
    TIME_WAIT = 60
    print 'gotit'
    while ( TIME_WAIT > ( time.time() - start )):
        print qq.get(timeout=60)
        print '\n\ngotit'
    dnsr.alive.clear()
    return


if __name__ == '__main__':
    import prettyprint
    import os,sys
    if not os.geteuid() == 0:
        sys.exit("\nOnly a root user can run this\n")
    test_dns_resolver()


