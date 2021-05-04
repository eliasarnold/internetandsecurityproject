from probes.Probe import Probe
from NetworkUtils import *


class ICMPProbe(Probe):
    def send(self, target_ip):
        # print(target_ip)
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        try:
            host = socket.gethostbyname(target_ip)
        except socket.gaierror:
            print('error')

        icmp = struct.pack('>BBHHH', 8, 0, 0, 0, 0)
        icmp = struct.pack('>BBHHH', 8, 0, 0, NetworkUtils.checksum_icmp(icmp), 0)
        sent = my_socket.sendto(icmp, (target_ip, 1))

    def receive(self):
        try:
            my_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        except socket.error as msg:
            return msg

        has_ip_header = False

        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        my_socket.bind((self.interface, 0x0800))
        result = [0, 0]
        while True:
            packet = my_socket.recvfrom(100)
            # Unterscheiden zwischen den einzelnen Headern
            ethernet_header = packet[0][0:14]
            ip_header = packet[0][14:34]

            # Die Bytes in Strings umwandeln
            ethernet_information = struct.unpack('!6s6s1h', ethernet_header)  # 0: Destination_mac, 1: Source_mac, 2: Type
            ip_information = struct.unpack('!1s1s2s2s1s1s1s1s2s4s4s', ip_header)
            # # Informationen aus den Strings auslesen
            ip_address_source = socket.inet_ntoa(ip_information[9])
            # ip_address_destination = socket.inet_ntoa(ip_information[10])
            ip_ttl = ord(ip_information[6])  # ord(<str>)" wandelt den <str>-Wert in ein <int>-Wert um (nach der ASCII-Codierung)!

            if int(ethernet_information[2]) == 2048 and ip_address_source == self.target_ip:
                # print("-----------ICMP-TEST-----------"
                #       "\nFrom ", ip_address_source,
                #       "\n-ttl: ", ip_ttl)
                result = [ip_address_source, ip_ttl]

            return result


