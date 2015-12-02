
import Queue
import threading
import subprocess
import shlex

from spartaparsers.Parser import Parser

class PortScanner(threading.Thread):
    def __init__(self, target, shared_queue=None):
        super(PortScanner, self).__init__()
        self.target = target
        self.HOST = 'nmap -n -sn -oX - {}'.format(target)
        self.CONNECT = 'nmap -sT -p1-500 -Pn -oX - {}'.format(target)
        self.STEALTH = 'nmap -sS -p1-500 -Pn -oX - {}'.format(target)
        if isinstance(shared_queue, Queue.Queue):
            self.shared_queue = shared_queue
        else:
            self.shared_queue = Queue.Queue()
        self.alive = True
        self.start()

    def run(self):
        try:
            nmap = subprocess.check_output(
                shlex.split(self.STEALTH)
            )
            parser = Parser(nmap)
            session = parser.get_session()
            record = {
                'start_time': session.start_time,
                'stop_time': session.finish_time,
                'total_hosts': int(session.total_hosts),
            }
            for host in parser.all_hosts():
                record[host.ip] = { 'status': host.status }
                for port in host.get_ports('tcp', 'open'):
                    srvc = host.get_service('tcp', port)
                    if srvc is None:
                        continue
                    record[host.ip][srvc.name] = int(port)
            self.shared_queue.put( { self.target: record } )
        except:
            # We don't know what we caught.
            raise
        finally:
            # Don't let a failure hang any waiting threads.
            self.alive = False


if __name__ == '__main__':
    import prettyprint
    import time
    import os, sys

    if not os.geteuid() == 0:
        sys.exit("\nOnly a root user can run this\n")

    sh_queue = Queue.Queue()
    psc = PortScanner('window-specialist.com', shared_queue=sh_queue)
    while psc.alive:
        time.sleep(0.1)
    prettyprint.pp(sh_queue.get(block=False))




