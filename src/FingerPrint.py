from queue import Queue
import signal
import os
import time
from NetworkUtils import *
from probes.FINProbe import FINProbe
from probes.ProbeReceiver import ProbeReceiver
from probes.ProbeSender import ProbeSender as ProbeSender
from probes.ICMPProbe import ICMPProbe
from probes.TCPProbe import TCPProbe


class FingerPrint:
    def __init__(self, interface, source_ip, mode, source_port, target_ip, target_port):
        self.mode = mode
        self.source_port = source_port
        self.source_ip = source_ip
        self.interface = interface
        self.target_ip = target_ip
        self.target_port = target_port

    def signal_handler(self, signum, frame):
        raise Exception("The test took too long")

    def execute_tests(self):
        open_port = NetworkUtils.find_open_port(self.source_ip, self.target_ip)

        if open_port == -2:
            print("No open port! Can't OS Fingerprint properly! Results will be inaccurate!")
            open_port = 0
        elif open_port == -1:
            print('Host is not active or protected by firewall!')
            return
        else:
            print("Found open port on: ", open_port)
            open_port = 0

        self.target_port = int(open_port)

        fin_probe = FINProbe(self.source_ip, int(self.source_port), self.target_ip, int(self.target_port), self.interface)
        tcp_probe = TCPProbe(self.source_ip, int(self.source_port), self.target_ip, int(self.target_port), self.interface)
        icmp_probe = ICMPProbe(self.source_ip, int(self.source_port), self.target_ip, int(self.target_port), self.interface)

        print('Doing FIN probe test...')
        time.sleep(3)
        fin_result = self.execute_test(fin_probe) # Falls der Test fehl schlägt, wird ['000000000000'] zurück gegeben
        time.sleep(3)
        print('Doing TCP probe test...')
        tcp_result = self.execute_test(tcp_probe) # Falls der Test fehl schlägt, wird 0 zurück gegeben
        print('Doing ICMP probe test...')
        icmp_result = self.execute_test(icmp_probe) # Falls der Test fehl schlägt, wird 0 zurück gegeben

        # if fin_result[1] == 'no answer received':
        #     print('------------FIN-TEST-----------\n',
        #     fin_result[1],'\n')
        # else:
        #     print('------------FIN-TEST-----------\n',
        #     'got answer: ',fin_result[0],'\n')

        guess = self.analyze([tcp_result, icmp_result, fin_result])

        self.create_table([tcp_result, icmp_result, fin_result, guess])

    def print_line(self, width):
        for i in range(1, width):
            print('-', end='')

    def create_table(self, results):
        width = int(os.get_terminal_size().columns/3)
        print(width)
        # self.print_line(width)
        print('----------------------------------------')
        print('|', 'Fingerprint Result'.center(width), '|')
        print('----------------------------------------')
        print('|', 'Target IP:'.center(width), '|')
        print('|', self.target_ip.center(width), '|')
        print('----------------------------------------')
        print('|', 'Target Port:'.center(width), '|')
        if self.target_port == 0:
            port = 'No open port'
        print('|', str(port).center(width), '|')
        print('----------------------------------------')
        print('|', 'TCP Probe:'.center(width), '|')
        print('|', ('TTL: '+str(results[0][0])).center(width), '|')
        print('|', ('TCP Header Length: '+str(results[0][0])).center(width), '|')
        print('|', ('TCP Flags: '+str(results[0][1])).center(width), '|')
        print('|', ('TCP Window Size: '+str(results[0][2])).center(width), '|')
        print('|', ('TCP Options: '+str(results[0][3])).center(width), '|')
        if len(results[0]) > 4:
            print('----------------------------------------')
            print('|', 'TCP Probe more information:'.center(width), '|')
            print('|', ('TCP Maximum Segment Size: '+str(results[0][5])).center(width), '|')
            print('|', ('TCP Sack Permitted: '+str(results[0][6])).center(width), '|')
            print('|', ('TCP NOP Bit: '+str(results[0][7])).center(width), '|')
            print('|', ('TCP Window Scale: '+str(results[0][8])).center(width), '|')
        print('----------------------------------------')
        print('|', 'ICMP Probe:'.center(width), '|')
        # print('|', ('TTL: '+str(results[1][0])).center(width), '|')
        print('----------------------------------------')
        print('|', 'FIN Probe:'.center(width), '|')
        print('|', ('Response Flags: '+str(results[2][0])).center(width), '|')
        print('----------------------------------------')
        print('|', ('Operating System Guessed: '+str(results[3])).center(width), '|')
        print('----------------------------------------')

    def fingerprint_miner(self):
        pass

    def execute_test(self, probe):
        probe_sender = ProbeSender(probe, self.source_ip, int(self.source_port), self.target_ip, int(self.target_port))
        result_queue = Queue()
        probe_receiver = ProbeReceiver(probe, self.interface, result_queue)
        signal.signal(signal.SIGALRM, self.signal_handler)
        signal.alarm(5) #Try for five seconds
        try:
            probe_receiver.start()
            probe_sender.start()
            result = probe_receiver.queue.get()
            signal.alarm(0) #Try for five seconds
            return result
        except Exception as msg:
            signal.alarm(0)  # Disable the alarm
            if isinstance(probe, FINProbe):
                return ['000000000000', 'no answer received']
            # return msg

    def analyze(self, result):
        tcp_result = result[0]  # Aufbau: [ip_ttl, tcp_length, tcp_flags(4*Reserved+8*Flags), tcp_window_size, tcp_options(optional)]
        icmp_result = result[1]  # Aufbau: [ip_address_source, ip_ttl]
        fin_result = result[2]  # Aufbau: ['000000000000','Aussage über Antwort']


        if tcp_result[0] > 120 and tcp_result[0] < 140: #Windows
                if tcp_result[3] > 16300 and tcp_result[3] < 16400:
                    return('Windows 2000')
                elif tcp_result[3] > 65500 and tcp_result[3] < 65600:
                    return('Windows XP')
                elif tcp_result[3] < 8200:
                    return 'Windows 7 and higher'
                else:
                    return 'No matching OS found'




        elif tcp_result[0] > 60 and tcp_result[0] < 70:  # Linux
            sack = 0
            # if len(tcp_result) >= 5:
            #     sack = tcp_result[4][1]
            #
            # if sack != 0:
            if fin_result[0] == '000000000000':
                return 'Mac OS'
            else:
                if tcp_result[3] < 5800 and tcp_result[3] > 5700:
                    return 'Google Linux'
                else:
                    return 'Linux'

        elif tcp_result[0] > 250 and tcp_result[0] < 260:  # Cisco
            return 'Cisco IOS'
        else:
            return 'No matching OS found'
