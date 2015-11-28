from region_trace import TraceRoute


class ReconEngine(object):

    def __init__(self):
        self.dnsr = DNSResolver()
        self.tracerotue_queue = Queue.Queue()

    def traceroute(self, ip):
        TraceRoute(ip, self.traceroute_queue)



