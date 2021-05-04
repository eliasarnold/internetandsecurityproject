from struct import pack

from probes.Probe import Probe
from NetworkUtils import *


class FINProbe(Probe):

    def send(self, target_ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error as msg:
            print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            # sys.exit()

        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        packet = ''
        source_ip = self.source_ip
        destination_ip = target_ip
        version = 4
        ihl = 5
        tot_len = 20
        tos = 0
        frag_off = 0
        id = 37324
        ttl = 64
        protocol = socket.IPPROTO_TCP
        check = 10
        saddr = socket.inet_aton(source_ip)
        daddr = socket.inet_aton(destination_ip)
        ihl_version = (version << 4) + ihl
        ip_header = pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

        source = self.source_port
        dest = self.target_port
        seq = 0
        ack_seq = 0
        doff = 5
        fin_bit = 1
        syn_bit = 1
        rst_bit = 0
        psh_bit = 0
        ack_bit = 0
        urg_bit = 0
        window = socket.htons(5840)
        check = 0
        urg_ptr = 0

        tcp_flags_assembled = fin_bit + (syn_bit << 1) + (rst_bit << 2) + (psh_bit <<3) + (ack_bit << 4) + (urg_bit << 5)
        offset_res = (doff << 4) + 0
        tcp_header = pack('!HHLLBBHHH', source, dest, seq, ack_seq, offset_res, tcp_flags_assembled,  window, check, urg_ptr)

        source_address = socket.inet_aton(source_ip)
        destination_address = socket.inet_aton(destination_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)

        psh = pack('!4s4sBBH', source_address, destination_address, placeholder, protocol, tcp_length)
        psh += tcp_header
        tcp_checksum = NetworkUtils.checksum_tcp(psh)

        tcp_header = pack('!HHLLBBHHH', source, dest, seq, ack_seq, offset_res, tcp_flags_assembled,  window, tcp_checksum , urg_ptr)
        packet = ip_header + tcp_header
        s.sendto(packet, (destination_ip, 0))

    def receive(self):
        try:
            my_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        except socket.error as msg:
            return msg

        has_ip_header = False

        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        my_socket.bind((self.interface, 0x0800))
        result = 0
        while True:
            packet = my_socket.recvfrom(100)
            # Unterscheiden zwischen den einzelnen Headern
            ethernet_header = packet[0][0:14]
            ip_header = packet[0][14:34]
            tcp_header_default = packet[0][34:54]

            # Die Bytes in Strings umwandeln
            ethernet_information = struct.unpack('!6s6s1h', ethernet_header)  # 0: Destination_mac, 1: Source_mac, 2: Type
            ip_information = struct.unpack('!1s1s2s2s1s1s1s1s2s4s4s', ip_header)
            tcp_information_default = struct.unpack('!2s2s4s4s1s1s1h2s2s', tcp_header_default)

            # Informationen aus den Strings auslesen
            ip_address_source = socket.inet_ntoa(ip_information[9])
            ip_address_destination = socket.inet_ntoa(ip_information[10])
            ip_ttl = ord(ip_information[6])  # ord(<str>)" wandelt den <str>-Wert in ein <int>-Wert um (nach der ASCII-Codierung)!
            tcp_length_with_flags_bin_teil_1 = bin(ord(tcp_information_default[4]))[2:].zfill(8)  # gives something like 0b1010000010100000 with 2*8=16 bits
            tcp_length = tcp_length_with_flags_bin_teil_1[0:4]
            tcp_length_with_flags_bin_teil_2 = bin(ord(tcp_information_default[5]))[2:].zfill(8)
            tcp_window_size = int(tcp_information_default[6])

            if int(ethernet_information[2]) == 2048 and ip_address_source == self.target_ip:
                result = [tcp_length_with_flags_bin_teil_1[4:8] + tcp_length_with_flags_bin_teil_2,'answer received']

            if result != 0:
                return result
