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


TCP_ELEMS = (
    'version', 'ip_header_length', 'ttl',
    'protocol', 'src_address', 'dest_address',
    'src_port', 'dest_port', 'sequence_number',
    'ack', 'tcp_header_length'
)

UDP_ELEMS = (
    'version', 'ip_header_length', 'ttl',
    'protocol', 'src_address', 'dest_address',
    'src_port', 'dest_port', 'length',
    'checksum', 'data'
)

ICMP_ELEMS = (
    'version', 'ip_header_length', 'ttl',
    'protocol', 'src_address', 'dest_address',
    'type', 'code', 'checksum'
)

TCP_PACKET = namedtuple('tcp_packet', TCP_ELEMS)
UDP_PACKET = namedtuple('udp_packet', UDP_ELEMS)
ICMP_PACKET = namedtuple('icmp_packet', ICMP_ELEMS)

UDP_DNS_PORT = 53
PENDING_DNS_REQUESTS = {}


# Networkin Protocol Numbers
ICMP_PROTO = 1
TCP_PROTO = 6
ETH_PROTO = 8
UDP_PROTO = 17

def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:" % (ord(a[0]), ord(a[1]), ord(a[2]))
  b += "%.2x:%.2x:%.2x" % (ord(a[3]), ord(a[4]), ord(a[5]))
  return b

def receive_raw_packet(sock):
    #Convert a string of 6 characters of ethernet address into a dash separated hex string
    #create a AF_PACKET type raw socket (thats basically packet level)
    #define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
    packet = sock.recvfrom(65565)

    #packet string from tuple
    packet = packet[0]

    #parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    # print 'Destination MAC : ' + eth_addr(packet[0:6]),
    # print ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
    # print ' Protocol : ' + str(eth_protocol)

    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == ETH_PROTO:
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]

        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        # print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl),
        # print ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol),
        # print ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

        #TCP protocol
        if protocol == TCP_PROTO:
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]

            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            # print 'Source Port : ' + str(source_port) + ' Dest Port : ',
            # print str(dest_port) + ' Sequence Number : ' + str(sequence),
            # print ' Acknowledgement : ' + str(acknowledgement),
            # print ' TCP header length : ' + str(tcph_length)
            ret_v = TCP_PACKET(
                            version, ihl, ttl,
                            protocol, s_addr, d_addr,
                            source_port, dest_port, sequence,
                            acknowledgement, tcph_length
            )

            # h_size = eth_length + iph_length + tcph_length * 4
            # data_size = len(packet) - h_size

            # #get data from the packet
            # data = packet[h_size:]

            # print 'Data : ' + data

        #ICMP Packets
        elif protocol == ICMP_PROTO:
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

            # print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
            ret_v = ICMP_PACKET(
                version, ihl, ttl,
                protocol, s_addr, d_addr,
                icmp_type, code, checksum
            )

            # h_size = eth_length + iph_length + icmph_length
            # data_size = len(packet) - h_size

            # #get data from the packet
            # data = packet[h_size:]

            # print 'Data : ' + data

        #UDP packets
        elif protocol == UDP_PROTO:
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            # print 'Source Port : ' + str(source_port) + ' Dest Port : ',
            # print str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)

            if dest_port == UDP_DNS_PORT or dest_port in PENDING_DNS_REQUESTS:
                # This might be a DNS packet.
                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size
                data = packet[h_size-2:]
            else:
                # This isn't a DNS packet.
                data = None

            ret_v = UDP_PACKET(
                version, ihl, ttl,
                protocol, s_addr, d_addr,
                source_port, dest_port, length,
                checksum, data
            )

            # print 'Data : ' + data

        #some other IP packet like IGMP
        else :
            print 'Protocol other than TCP/UDP/ICMP'
            return None
    else:
        return None
    return ret_v

def receive_tcp_packet(sock):
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
    pkt_obj = TCP_PACKET(
        version=pkt_version,
         ip_header_length=ihl,
         ttl=ttl_num,
         protocol=protocol_type,
         src_address=s_addr,
         dest_address=d_addr,
         src_port=source_port_num,
         dest_port=dest_port_num,
         sequence_number=sequence,
         ack=acknowledgement,
         tcp_header_length=tcph_length
    )
    return pkt_obj

class DNSParser(threading.Thread):

    def __init__(self, shared_queue=None):
        super(DNSParser, self).__init__()

        if isinstance(shared_queue, Queue.Queue):
            self.shared_queue = shared_queue
        else:
            self.shared_queue = Queue.Queue()
        self.alive = threading.Event()
        self.alive.set()
        self.start()

    def run(self):
        while self.alive.isSet():
            try:
                # Block for 1/10th of a second to service self.alive.isSet()
                udp_packet = self.shared_queue.get(timeout=0.1)
            except Queue.Empty:
                pass

    def get_queue(self):
        return self.shared_queue


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
            pkt_obj = receive_tcp_packet(self.sock)
            # Send the packet details upstream.
            self.shared_queue.put(pkt_obj)

    def get_queue(self):
        return self.shared_queue


def test_packet_sniffer(max_packets=100):
    """Receive a number (max_packets) of packets to test PacketSniffer(object)
    """
    shared_queue = Queue.Queue()
    pckt_sniffer = PacketSniffer(shared_queue)
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
    pckt_sniffer.alive.clear()
    # Make sure the Queue is Empty.
    counter = 0
    while True:
        try:
            pkt_obj = shared_queue.get(block=False)
            print 'leftover-{}: {}'.format(counter, pkt_obj)
        except Queue.Empty:
            break
        counter += 1
    print 'TEST SNIFFER COMPLETE\n\n'

def test_receive_tcp_packet(max_packets=100):
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
        pkt_obj = receive_tcp_packet(sock)
        print '{}: {}\n'.format(counter, pkt_obj.__repr__())
        counter += 1
    print 'TEST RECEIVE COMPLETE\n\n'

def test_receive_raw_packet(max_packets=100):
    """
    """
    from prettyprint import pp
    global PENDING_DNS_REQUESTS
    try:
        sock = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()
    pkt_seen = {}
    counter = 0
    while counter < max_packets:
        # receive a packet
        pkt_obj = receive_raw_packet(sock)
        if pkt_obj and pkt_obj.protocol == UDP_PROTO:
            if pkt_obj.data:
                # Host name lookup
                # This is a sen't packet.
                if pkt_obj.data[:2].__repr__() not in pkt_seen:
                    print 's', pkt_obj.data[2:].__repr__()
                    pkt_seen[pkt_obj.data[:2].__repr__()] = True
                    PENDING_DNS_REQUESTS[pkt_obj.src_port] = pkt_obj.data[:2].__repr__()
                if pkt_obj.dest_port in PENDING_DNS_REQUESTS:
                    print 'd', pkt_obj.data[10:]
                counter += 1

    pp (pkt_seen)
    pp(PENDING_DNS_REQUESTS)
    print 'TEST RECEIVE RAW COMPLETE\n\n'


if __name__ == '__main__':
    import time
    import os, sys
    if not os.geteuid() == 0:
        sys.exit("\nOnly a root user can run this\n")

    #dnsp = DNSParser()
    test_receive_raw_packet()
    #dnsp.alive.clear()
    # time.sleep(5)
    # test_receive_tcp_packet()
    # time.sleep(5)
    # test_packet_sniffer()


