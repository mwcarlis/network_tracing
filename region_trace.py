
from collections import namedtuple
import subprocess
import re

Header = namedtuple('header', ['dest', 'dest_ip', 'max_hops', 'packet_Blen'])
Hop = namedtuple('HOST', ['hostname', 'ip'])
Delay = namedtuple('delay', ['delay', 'unit'])

class IpGetter(object):
    master = None
    def __init__(self):
        if not self.master:
            self.master = self
        return self.master
    @staticmethod
    def from_trace_route(tr):
        for item in tr:
            if isinstance(tr, Hop):
                return tr.dest_ip

    def __getitem__(self, key):
        if isinstance(key, Hop):
            return tr.dest_ip
        if isinstance(key, TraceRoute):
            pass


class TraceRoute(object):
    PROGRAM = '/usr/bin/traceroute'
    # An IP Address '(192.151.15.15)' Exclude the -> ()
    IP_RE = r'\(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\)'

    # A Hostname website.com or my.website.com .. etc
    #   at least two words with a period seperation with numbers.
    HOSTNAME_RE = r'(([a-z0-9\-]*\.)+[a-zA-Z0-9]+)'

    # A Delay time regular expression.  ####.###
    DELAY_RE = r'([0-9]{1,4}\.[0-9]{1,3}$)'
    def __init__(self, ip):
        self.destination_ip = ip
        self.trace_map = {}
        self._run_trace()
        self._build_table()

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

    def __iter__(self):
        for key in sorted(self.trace_map.keys()):
            if key == 0:
                continue
            yield self.trace_map[key]

    def __getitem__(self, key):
        return self.trace_map[key]


    def _parser(self, table):
        """A traceroute STDOUT parser.
        """
        IP_HOST_S = 0
        IP_S      = 1
        DELAY_S = 2
        D_UNIT_S  = 3
        ERROR_S   = 99

        milisec = 'ms'
        # Header = namedtuple('header', ['dest', 'dest_ip', 'max_hops', 'packet_Blen'])
        print table
        h_row= table[0]
        header = Header(h_row[2], h_row[3].strip('(),'), int(h_row[4]), int(h_row[7]))
        trace_globs = { 0: header}
        for count, row in enumerate(table[1:]):
            row_glob = []
            state = IP_HOST_S
            for cnt, item in enumerate(row[1:]):
                if item == '*':
                    if count + 1 not in trace_globs:
                        trace_globs[count + 1] = None
                    continue
                if state == IP_HOST_S:
                    # Parse the HOSTNAME or IP if not HOSTNAME.
                    # IP RE doesn't match hostnames.  Test IP first.
                    match = re.match(self.IP_RE, item)
                    if not match:
                        # Our hostname RE also matches IP's.  Test IP first.
                        match = re.match(self.HOSTNAME_RE, item)
                    if match:
                        ### Next State
                        hostname = match.groups()[0]
                        state = IP_S
                        continue
                    print 'err ip host s'
                    state = ERROR_S
                elif state == IP_S:
                    # Parse the IP Section.
                    match = re.match(self.IP_RE, item)
                    if match:
                        ### Next state
                        ip_addr = match.groups()[0]
                        hop = Hop(hostname, ip_addr)
                        # print hop,
                        row_glob.append(hop)
                        state = DELAY_S
                        continue
                    print 'err ip s'
                    state = ERROR_S
                elif state == DELAY_S:
                    # Parse the value of delay.
                    match = re.match(self.DELAY_RE, item)
                    if match:
                        ### Next state
                        delay = match.groups()[0]
                        state = D_UNIT_S
                        continue
                    print 'err delay s'
                    state = ERROR_S
                elif state == D_UNIT_S:
                    # Parse the unit of the delay.
                    if milisec == item:
                        time_delay = Delay(delay, milisec)
                        # print time_delay,
                        row_glob.append(time_delay)
                        # Is this the last item?
                        if cnt + 2 < len(row):
                            ### Next state
                            next_item = row[cnt+2]
                            delay_match = re.match(self.DELAY_RE, next_item)
                            if delay_match:
                                # Next is another delay.
                                state = DELAY_S
                                continue
                            ip_match = re.match(self.IP_RE, next_item)
                            hinfo_match = re.match(self.HOSTNAME_RE, next_item)
                            if ip_match or hinfo_match:
                                # Next is a host or IP. Restart.
                                state = IP_HOST_S
                                continue
                            # This is terminal.
                            continue
                    # We encountered an error.
                    print 'err d unit s'
                    state = ERROR_S
                else:
                    raise Exception('Undefined state {}'.format(cnt))
            #print ''
            # Go to the next row.  Make this row first.
            if count + 1 not in trace_globs:
                trace_globs[count+1] = tuple(row_glob)
        return trace_globs




class whois(object):
    def __init__(self, ip):
        pass

if __name__ == '__main__':
    pass
