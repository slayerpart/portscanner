#
# Requirements: pcapy
# running on Mac OS 10.11
# python 3.4.3
#

import sys
import socket
import thread
from struct import *
import pcapy
import time
import random


class  Portscanner:
    '''
    Represents a Portscanner providing Connect- and SYN-Scan methods
    '''
    def __init__(self, ip, method, ports):

        # Instance variables
        self.operating = False
        self.open_ports = set()
        self.port_range = ports
        self.remote_ip = ip

        if method == "CONNECT":
            self.connect_scan()
        elif method == "SYN":
            self.syn_scan()

    def connect_scan(self):
        for port in self.port_range:
            try:
                sock = socket.socket()
                sock.settimeout(2) # avoid blocking due to closed ports
                sock.connect((self.remote_ip, port))
                sock.close()
                self.open_ports.add(port)
            except(socket.error):
                pass
        self.print_results()

    # get own global ip by using udp sockets
    def get_ip_address(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.2.3.4", 80))
        return s.getsockname()[0]

    def syn_scan(self):
        self.operating = True

        #create a raw socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.settimeout(2)
        except socket.error, msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()

        # start extra thread for sniffing response packets
        thread.start_new(self.sniff_packets, ())
        time.sleep(0.8)

        # sending syn segments to remote host
        for port in self.port_range:
            packet = self.create_syn_packet(port)
            s.sendto(packet, (self.remote_ip, port))

        time.sleep(3) # wait for last incomming packets
        self.operating = False
        s.close()
        self.print_results()

    def sniff_packets(self):
        dev = pcapy.findalldevs()[0]

        p = pcapy.open_live(dev, 1600, 0, 100)
        p.setfilter('src host {0}'.format(self.remote_ip)) # Only packets with set SYN-ACK flag received
        try:
            while self.operating:
                p.dispatch(1, self.check_ack)

        except KeyboardInterrupt:
            print '%s' % sys.exc_type
            print 'shutting down'
            print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()

    def check_ack(self, pktlen, data):
        if not data:
            return

        if data[12:14] == '\x08\x00':
            parsed_data = self.parse_packet(data[14:])

            # check if the packet src is the target and if the syn|ack-flags are set
            if parsed_data[0] == self.remote_ip and parsed_data[1] == 1 and parsed_data[2] == 1:
                # save the open port and send the packet to the os detection
                self.open_ports.add(parsed_data[3])

    def parse_packet(self, packet):
        data = ['src_ip', 'syn-flag', 'ack-flag', 'port']

        header_length = ord(packet[0]) & 0x0f

        # src ip
        data[0] = socket.inet_ntoa(packet[12:16])

        # syn-flag
        data[1] = ord(packet[4 * header_length + 13]) >> 1 & 0x1

        # ack-flag
        data[2] = ord(packet[4 * header_length + 13]) >> 4 & 0x1

        # port number
        data[3] = (ord(packet[4 * header_length]) << 8) + ord(packet[4 * header_length + 1])

        return data

    # source: http://www.binarytides.com/raw-socket-programming-in-python-linux
    def checksum(self, msg):
        s = 0
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
            s = s + w

        s = (s>>16) + (s & 0xffff)
        s = s + (s >> 16);
        s = ~s & 0xffff

        return s

    def print_results(self):
        if self.open_ports is not None:
            sorted_results = sorted(self.open_ports)

            print("Port    Service")
            print("-" * 8)

            for port in sorted_results:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = 'unknown'
                print(str(port) + " " * (8 - len(str(port))) + str(service))
        else:
            print("No open ports found.")

    def create_syn_packet(self, port):

        # tcp header fields
        src_port = random.randint(20000, 65535) # create random port
        dest_port = port
        seq_nr = 454
        ack_nr = 0
        offset = 5

        # flags
        urg = 0
        ack = 0
        psh = 0
        rst = 0
        syn = 1
        fin = 0

        window = socket.htons(5840)
        checksum = 0
        urg_pointer = 0

        packet_offset = (offset << 4) | 0
        flags = fin | (syn << 1) | (rst << 2) | (psh << 3) | (ack << 4) | (urg << 5)

        # build a pseudo header to calculate the checksum
        tcp_header = pack('!HHLLBBHHH', src_port, dest_port, seq_nr, ack_nr, packet_offset,
                          flags,  window, checksum, urg_pointer)
s        psh_source = socket.inet_aton(self.get_ip_address())
        psh_dest = socket.inet_aton(self.remote_ip)
        psh_placeholder = 0
        psh_protocol = socket.IPPROTO_TCP
        psh_tcp_length = len(tcp_header)

        # build the pseudo packet
        psh = pack('!4s4sBBH', psh_source, psh_dest, psh_placeholder, psh_protocol, psh_tcp_length)
        psh = psh + tcp_header

        # calculate the checksum
        checksum = self.checksum(psh)

        # build the packet with the correct checksum
        tcp_header = pack("!HHLLBBH", src_port, dest_port, seq_nr, ack_nr, packet_offset, flags, window)\
                     + pack('H', checksum) + pack('!H', urg_pointer)

        return tcp_header


if __name__ == "__main__":

    if sys.argv.__len__() != 4:
        print("Usage: scanner.py IP SCAN_METHOD LIST_OF_PORTS")
    if sys.argv[2] in ['SYN', 'CONNECT']:
        method = sys.argv[2]
    else:
        raise Exception('Invalid method')
    # convert string list into data list
    if "," in sys.argv[3] or "-" in sys.argv[3]:
        ports = sys.argv[3].split(",")
        port_range = []
        for port in ports:
            if "-" in port:
                p_range = [int(i) for i in port.split("-")]
                port_range.extend(range(p_range[0], p_range[1] + 1))
            else:
                port_range.extend(int(port))
    else:
        port_range = [int(sys.argv[3])]

     # check if port numbers are in port range
    for port in port_range:
        if port < 0 or port > 65535:
            raise Exception('port number out of range', port)

    try:
        ip = socket.gethostbyname(sys.argv[1])
    except(socket.gaierror):
        print("host " + sys.argv[1] + " does not exist")
        sys.exit("unknown host")
    # start all the scanning stuff here
    ps = Portscanner(ip, method, port_range)