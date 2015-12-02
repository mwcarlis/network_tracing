
from collections import namedtuple
import subprocess
import re
import threading
import Queue


Header = namedtuple('header', ['dest', 'dest_ip', 'max_hops', 'packet_Blen'])
Host = namedtuple('HOST', ['hostname', 'ip', 'delays', 'delay_unit'])


class IpGetter(object):
    master = None
    def __init__(self):
        if not self.master:
            self.master = self
        return self.master
    @staticmethod
    def from_trace_route(tr):
        for item in tr:
            if isinstance(tr, Host):
                return tr.dest_ip

    def __getitem__(self, key):
        if isinstance(key, Host):
            return tr.dest_ip
        if isinstance(key, TraceRoute):
            pass


class TraceRoute(threading.Thread):
    PROGRAM = '/usr/bin/traceroute'
    # An IP Address '(192.151.15.15)' Exclude the -> ()
    # IP_RE = r'\(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\)'
    IP_RE = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    TR_IP_RE = r'^\((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\)$'

    # A Hostname website.com or my.website.com .. etc
    #   at least two words with a period seperation with numbers.
    # HOSTNAME_RE = r'(([a-z0-9\-]*\.)+[a-zA-Z0-9]+)'
    HOSTNAME_RE = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'


    # A Delay time regular expression.  ####.###
    DELAY_RE = r'([0-9]{1,4}\.[0-9]{1,3}$)'
    def __init__(self, ip, shared_queue=None):
        super(TraceRoute, self).__init__()
        self.destination_ip = ip
        if isinstance(shared_queue, Queue.Queue):
            self.shared_queue = shared_queue
        else:
            self.shared_queue = Queue.Queue()
        self.trace_map = {}
        self.alive = True
        self.start()

    def _run_trace(self):
        trace = subprocess.check_output([self.PROGRAM, self.destination_ip])
        self.raw_trace = trace.strip()

    def _build_table(self):
        table = []
        for line in self.raw_trace.splitlines():
            # Split the line on whitespaces/tabs.
            row = re.split(r'[\s\t]*', line.strip())
            table.append(row)
        self.trace_map = self._parser(table)

    def run(self):
        try:
            self._run_trace()
            self._build_table()
            self.shared_queue.put(self.trace_map)
        except:
            raise
        finally:
            self.alive = False

    def completed(self):
        return self.finished

    def __iter__(self):
        for key in sorted(self.trace_map.keys()):
            if key == 0:
                continue
            yield self.trace_map[key]

    def __getitem__(self, key):
        return self.trace_map[key]

    def get_queue(self):
        return self.shared_queue

    # TR_IP_RE
    # HOSTNAME_RE =
    # DELAY_RE = r'([0-9]{1,4}\.[0-9]{1,3}$)'

    def _parser(self, table):
        """A traceroute STDOUT parser.
        """
        IP_HOST_S = 0
        DELAY_S = 1
        DELAY_UNIT = 2

        milisec = 'ms'
        # Header = namedtuple('header', ['dest', 'dest_ip', 'max_hops', 'packet_Blen'])
        h_row= table[0]
        header = Header(h_row[2], h_row[3].strip('(),'), int(h_row[4]), int(h_row[7]))
        trace_globs = { 0: header}
        this_ip = None
        for count, row in enumerate(table[1:]):
            delays = []
            state = IP_HOST_S
            for cnt, item in row[1:]:
                if '*' in item:
                    continue

                if re.match(self.HOSTNAME_RE, item):
                    # HOSTNAME is a superset of IP_RE
                    host = item

                    if this_ip and len(delays) > 0:
                        Host(hostname=host, ip=this_ip, delays=tuple(delays), delay_unit='ms')
                    delays = []
                    state = IP_HOST_S
                    continue
                elif re.match(self.TR_IP_RE, item):
                    # (IP) is a subset of HOSTNAME_RE
                    this_ip = item.strip('()')

                    state = DELAY_S
                    continue
                elif state == DELAY_S and re.match(self.DELAY_RE, item):
                    # Get the Delay number
                    state = DELAY_UNIT
                    delays.append(item)
                    continue
                elif state == DELAY_UNIT and 'ms' in item:
                    state = DELAY_S
                    continue
                else:
                    pass




            # Go to the next row.  Make this row first.
            if count + 1 not in trace_globs:
                trace_globs[count+1] = tuple(row_glob)
        return trace_globs


class whois(object):
    def __init__(self, ip):
        pass


def test_trace_route(domain='www.google.com'):
    """Test the trace route object on domain.
    """
    queue = Queue.Queue()
    trc = TraceRoute(domain, queue)
    return queue.get(block=True, timeout=30)

if __name__ == '__main__':
    import prettyprint
    prettyprint.pp(test_trace_route())

