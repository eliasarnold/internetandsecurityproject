from struct import pack

from probes.Probe import Probe
from NetworkUtils import *


class OptionsProbe(Probe):
    def send(self, target_ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error as msg:
            print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            return

        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        packet = ''
        source_ip = self.source_ip
        destination_ip = target_ip
        ihl = 5
        version = 4
        tos = 0
        tot_len = 20
        id = 37873
        frag_off = 0
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
        doff = 8
        fin_bit = 0
        syn_bit = 1
        rst_bit = 0
        psh_bit = 0
        ack_bit = 0
        urg_bit = 0
        window = socket.htons(5840)
        check = 0
        urg_ptr = 0
        mss_kind = 2
        mss_length = 4
        mss_value = 1222
        sack_kind = 4
        sack_length = 2
        sack_rfc_complier = 0
        window_kind = 3
        window_length = 3
        window_shift_count = 8

        offset_res = (doff << 4) + 0
        tcp_flags = fin_bit + (syn_bit << 1) + (rst_bit << 2) + (psh_bit << 3) + (ack_bit << 4) + (urg_bit << 5)

        tcp_header = pack('!HHLLBBHHHBBHBBHBBH', source, dest, seq, ack_seq, offset_res, tcp_flags,  window, check,
                          urg_ptr, mss_kind, mss_length, mss_value, sack_kind, sack_length, sack_rfc_complier,
                          window_kind, window_length, window_shift_count)

        source_address = socket.inet_aton(source_ip)
        dest_address = socket.inet_aton(destination_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)

        psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
        psh += tcp_header

        tcp_checksum = NetworkUtils.checksum_tcp(psh)
        tcp_header = pack('!HHLLBBHHHBBHBBHBBH', source, dest, seq, ack_seq, offset_res, tcp_flags,  window,
                          tcp_checksum, urg_ptr, mss_kind, mss_length, mss_value, sack_kind, sack_length, sack_rfc_complier,
                          window_kind, window_length, window_shift_count)

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

        while True:
            packet = my_socket.recvfrom(100)
            # Unterscheiden zwischen den einzelnen Headern
            ethernet_header = packet[0][0:14]
            ip_header = packet[0][14:34]
            tcp_header_default = packet[0][34:54]

            # Die Bytes in Strings umwandeln
            ethernet_information = struct.unpack('!6s6s1h',ethernet_header)  # 0: Destination_mac, 1: Source_mac, 2: Type
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
                print("------------TCP-TEST-----------"
                      "\nFrom ", ip_address_source,
                      "\n-ttl: ", ip_ttl,
                      "\n-tcp-len: ", int(tcp_length, 2) * 4,
                      "\n-tcp-flags ", tcp_length_with_flags_bin_teil_1[4:8] + tcp_length_with_flags_bin_teil_2,
                      "\n-window-size: ", tcp_window_size)
                result = [ip_ttl, int(tcp_length, 2)*4, tcp_length_with_flags_bin_teil_1[4:8] + tcp_length_with_flags_bin_teil_2, tcp_window_size]

                if int(tcp_length, 2) >= 10:
                    print("\nThe TCP-Header provides more information...")
                    tcp_header_option = packet[0][54:74]
                    tcp_information_option = struct.unpack('!2s1H1B1s10s1?2s1B', tcp_header_option)
                    tcp_mss = tcp_information_option[1]
                    tcp_sack_permitted = tcp_information_option[2]
                    tcp_no_operation = tcp_information_option[5]
                    tcp_window_scale = tcp_information_option[7]
                    print(
                        "\n-MSS: ", tcp_mss,
                        "\n-SACK-Permitted: ", tcp_sack_permitted,
                        "\n-NoOP: ", tcp_no_operation,
                        "\n-Window scale: ", tcp_window_scale
                    )
                    result.append([tcp_mss, tcp_sack_permitted, tcp_no_operation, tcp_window_scale])

                return result
