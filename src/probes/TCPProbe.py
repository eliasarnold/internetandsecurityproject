import socket
import time
import struct
from probes.Probe import Probe


class TCPProbe(Probe):
    def send(self, target_ip):
        time.sleep(1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.source_ip, self.source_port))
        try:
            s.connect((target_ip, self.target_port))
        except socket.error as msg:
            # print("Connection doesn't accept TCP connections on that port!")
            pass
        s.close()

    def receive(self):
        try:
            my_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        except socket.error as msg:
            pass
            # return msg

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
            result = 0
            if int(ethernet_information[2]) == 2048 and ip_address_source == self.target_ip:
                # print("------------TCP-TEST-----------"
                #       "\nFrom ", ip_address_source,
                #       "\n-ttl: ", ip_ttl,
                #       "\n-tcp-len: ", int(tcp_length, 2) * 4,
                #       "\n-tcp-flags ", tcp_length_with_flags_bin_teil_1[4:8] + tcp_length_with_flags_bin_teil_2,
                #       "\n-window-size: ", tcp_window_size)
                result = [ip_ttl, int(tcp_length, 2)*4, tcp_length_with_flags_bin_teil_1[4:8] + tcp_length_with_flags_bin_teil_2, tcp_window_size]
                if int(tcp_length, 2) >= 10:
                    print("\nThe TCP-Header provides more information...")
                    tcp_header_option = packet[0][54:74]
                    tcp_information_option = struct.unpack('!2s1H1B1s10s1?2s1B', tcp_header_option)
                    tcp_mss = tcp_information_option[1]
                    tcp_sack_permitted = tcp_information_option[2]
                    tcp_no_operation = tcp_information_option[5]
                    tcp_window_scale = tcp_information_option[7]
                    # print(
                    #     "\n-MSS: ", tcp_mss,
                    #     "\n-SACK-Permitted: ", tcp_sack_permitted,
                    #     "\n-NoOP: ", tcp_no_operation,
                    #     "\n-Window scale: ", tcp_window_scale
                    # )
                    result.append([tcp_mss, tcp_sack_permitted, tcp_no_operation, tcp_window_scale])

                return result
