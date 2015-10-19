#!/usr/bin/python

"""
Packet sniffer in python for Linux
Sniffs only incoming TCP packet
"""

import socket, sys
from struct import *
from collections import namedtuple

import threading
import Queue


PACKET_ELEMS = (
    'version', 'ip_header_length', 'ttl',
    'protocol', 'src_address', 'dest_address',
    'src_port', 'dest_port', 'sequence_number',
    'ack', 'tcp_header_length'
)
PACKET = namedtuple('packet', PACKET_ELEMS)


def receive_packet(sock):
    """A function to receive a packet.
    """
    packet = sock.recvfrom(65565)
    #packet string from tuple
    packet = packet[0]

    #take first 20 characters for the ip header
    ip_header = packet[0:20]
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
    version_ihl = iph[0]

    # Interesting IP items unpacked.
    pkt_version = version_ihl >> 4
    ihl = version_ihl & 0xF
    ttl_num = iph[5]
    protocol_type = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);

    # Get the TCP Header
    iph_length = ihl * 4
    tcp_header = packet[iph_length:iph_length+20]
    tcph = unpack('!HHLLBBHHH' , tcp_header)

    # Interesting TCP items unpacked.
    source_port_num = tcph[0]
    dest_port_num = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4

    # Get the data segment of the Packet.
    # h_size = iph_length + tcph_length * 4
    # data_size = len(packet) - h_size
    # #get data from the packet
    # data = packet[h_size:]

    # Pack up the packet details.
    pkt_obj = PACKET(version=pkt_version,
                     ip_header_length=ihl,
                     ttl=ttl_num,
                     protocol=protocol_type,
                     src_address=s_addr,
                     dest_address=d_addr,
                     src_port=source_port_num,
                     dest_port=dest_port_num,
                     sequence_number=sequence,
                     ack=acknowledgement,
                     tcp_header_length=tcph_length)
    return pkt_obj

class PacketSniffer(threading.Thread):
    """A Packet Sniffing object with threading.
    """

    def __init__(self, shared_queue=None):
        super(PacketSniffer, self).__init__()

        if isinstance(shared_queue, Queue.Queue):
            self.shared_queue = shared_queue
        else:
            self.shared_queue = Queue.Queue()
        self.alive = threading.Event()
        self.alive.set()
        self.start()

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error, msg:
            self.alive.clear()
            raise

    def run(self):
        self.connect()
        while self.alive.isSet():
            pkt_obj = receive_packet(self.sock)
            # Send the packet details upstream.
            self.shared_queue.put(pkt_obj)

    def get_queue(self):
        return self.shared_queue


def test_sniffer(max_packets=100):
    """Receive a number (max_packets) of packets to test PacketSniffer(object)
    """
    shared_queue = Queue.Queue()
    pck = PacketSniffer(shared_queue)
    counter = 0
    while counter < max_packets:
        try:
            pkt_obj = shared_queue.get(block=True)
            print '{}: {}\n'.format(counter, pkt_obj)
            shared_queue.task_done()
        except Queue.Empty:
            continue
        counter += 1
    # Tell the thread to die.
    pck.alive.clear()
    # Make sure the Queue is Empty.
    counter = 0
    while True:
        try:
            pkt_obj = shared_queue.get(block=False)
            print 'leftover-{}: {}'.format(counter, pkt_obj)
        except Queue.Empty:
            break
        counter += 1
    print 'TEST SNIFFER COMPLETE'

def test_receive(max_packets=100):
    """Receive a number (max_packets) of packets as a test and print to stout.
    """
    try:
        #create an INET, STREAMing socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error , msg:
        message = 'Socket could not be created. Error Code : '
        print message + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    counter = 0
    while counter < max_packets:
        # receive a packet
        pkt_obj = receive_packet(sock)
        print '{}: {}\n'.format(counter, pkt_obj.__repr__())
        counter += 1
    print 'TEST RECEIVE COMPLETE'


if __name__ == '__main__':
    test_receive()
    test_sniffer()


