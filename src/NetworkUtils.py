import os
import signal
import socket
import struct
import sys
from time import sleep


class NetworkUtils: 
    @staticmethod
    def get_interfaces(): 
        interfaces = os.listdir('/sys/class/net/') 
        return interfaces

    @staticmethod
    def signal_handler(self, signum, frame):
        raise Exception("The test took to long")

    @staticmethod
    def find_open_port(source_ip, target_ip):
        signal.signal(signal.SIGALRM, NetworkUtils.signal_handler)
        signal.alarm(5)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((source_ip, 0))

            common_ports = [22, 23, 25, 53, 80, 110, 111, 113, 135, 139, 143, 199, 256, 443, 445, 554, 587, 993, 995,
                            1720, 1723, 3306, 3389, 5900, 8080, 8888, 10257]

            open_port = -2

            for value in common_ports:
                try:
                    s.connect((target_ip, value))
                    open_port = value
                    break
                except socket.error as msg:
                    # print("Port", i, 'is not open!')
                    pass

            # for i in range(1, 65535):
            #     try:
            #         s.connect((target_ip, i))
            #         return i
            #     except socket.error as msg:
            #         # print("Port", i, 'is not open!')
            #         pass
            s.close()
            signal.alarm(0)  # Disable the alarm
            return open_port

        except Exception as msg:
            signal.alarm(0)  # Disable the alarm
            return -1

    @staticmethod
    def full_port_scan(source_ip, target_ip, start_port, end_port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((source_ip, 8080))

        open_ports = ''

        for i in range(start_port, end_port+1):
            try:
                s.connect((target_ip, i))
                # print("Port", i, 'is open!')
                open_ports = open_ports + str(i) + ', '

            except socket.error as msg:
                # print("Port", i, 'is not open!')
                pass

        if len(open_ports) == 0:
            print('No open ports!')
        else:
            print('Open ports:')
            print('[', open_ports[:len(open_ports)-2], ']', sep='')

        s.close()

    @staticmethod
    def checksum_tcp(msg):
        s = 0
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = ((msg[i]) << 8) + (msg[i+1])
            s = s + w

        s = (s>>16) + (s & 0xffff)
        #s = s + (s >> 16)
        #complement and mask to 4 byte short
        s = ~s & 0xffff
        return s

    @staticmethod
    def get_ip_from_hostname(interface, adress):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error as msg:
            print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            # sys.exit()

        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return s.gethostbyname_ex(adress)


    @staticmethod
    def half_port_scan(source_ip, target_ip, start_port, end_port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error as msg:
            print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            # sys.exit()

        for i in range(start_port, end_port):
            # time.sleep(1)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            packet = ''
            source_ip = source_ip
            destination_ip = target_ip
            ihl = 5
            version = 4
            tos = 0
            tot_len = 20
            id = 54321  #Id of this packet
            frag_off = 0
            ttl = 44
            protocol = socket.IPPROTO_TCP
            check = 10  # python seems to correctly fill the checksum
            saddr = socket.inet_aton(source_ip)  #Spoof the source ip address if you want to
            daddr = socket.inet_aton(destination_ip)
            ihl_version = (version << 4) + ihl
            ip_header = struct.pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
            source = 12345  # source port
            dest = i  # destination port
            seq = 0
            ack_seq = 0
            doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
            fin = 0
            syn = 1
            rst = 0
            psh = 0
            ack = 0
            urg = 0
            window = socket.htons(5840)
            check = 0
            urg_ptr = 0
            offset_res = (doff << 4) + 0
            tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
            tcp_header = struct.pack('!HHLLBBHHH', source, dest, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)
            source_address = socket.inet_aton(source_ip)
            dest_address = socket.inet_aton(destination_ip)
            placeholder = 0
            protocol = socket.IPPROTO_TCP
            tcp_length = len(tcp_header)
            psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
            psh += tcp_header
            tcp_checksum = NetworkUtils.checksum_tcp(psh)
            tcp_header = struct.pack('!HHLLBBHHH', source, dest, seq, ack_seq, offset_res, tcp_flags, window, tcp_checksum, urg_ptr)
            packet = ip_header + tcp_header
            s.sendto(packet, (destination_ip, 0))

    @staticmethod 
    def get_ip(interface): 
        f = os.popen('ifconfig ' + interface + ' | grep "inet\ addr" | cut -d: -f2 | cut -d" " -f1') 
        your_ip = f.read() 
        return your_ip

    @staticmethod
    def checksum_icmp(source_string):
        """
        AUTHOR: https://github.com/samuel/python-ping/blob/master/ping.py
        I'm not too confident that this is right but testing seems
        to suggest that it gives the same answers as in_cksum in ping.c
        """
        sum = 0
        countTo = (len(source_string)/2)*2
        count = 0
        while count<countTo:
            thisVal = source_string[count + 1]*256 + source_string[count]
            sum = sum + thisVal
            sum = sum & 0xffffffff # Necessary?
            count = count + 2

        if countTo<len(source_string):
            sum = sum + ord(source_string[len(source_string) - 1])
            sum = sum & 0xffffffff # Necessary?

        sum = (sum >> 16)  +  (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff

        # Swap bytes. Bugger me if I know why.
        answer = answer >> 8 | (answer << 8 & 0xff00)

        return answer

    @staticmethod
    def get_result(probe_name, interface, zielip):
        if probe_name == "ICMPProbe":
            result = NetworkUtils.receive_icmp(interface, zielip)
        elif probe_name == "TCPProbe":
            result = NetworkUtils.receive_tcp(interface, zielip)
        else:
            result = ["Something went wrong", probe_name]

        return result
