import readline 
from enum import IntEnum
from NetworkUtils import *
from FingerPrint import *

 
class Commands(IntEnum): 
    NONE = 0 
    HELP = 1 
    FINGERPRINT = 2 
    INTERFACES = 3
    TEST = 4
    IP = 5
    PORT = 6
    EXIT = 7


class Application: 
    def __init__(self): 
        self.running = True
        self.interfaces = NetworkUtils.get_interfaces()

    def run(self):
        Application.intro()
        while self.running:
            self.run_command(input('>> '))
        return

    def run_command(self, command):
        command = command.split(' ') 
        try: 
            if len(command) >= 2 and Commands[command[0].upper()] != Commands.HELP: 
                command[0] = Commands[command[0].upper()] 
            elif len(command) == 1: 
                command = [Commands[command[0].upper()]]
            else: 
                command = [Commands[command[0].upper()], Commands[command[1].upper()]] 
        except Exception:
            Application.help()
 
        if command[0] == Commands.HELP: 
            if len(command) == 2:
                Application.help(command[1])
            else:
                Application.help()
        elif command[0] == Commands.EXIT:
            print('Bye bye, sleep well!')
            self.running = False
        elif command[0] == Commands.INTERFACES:
            self.print_interfaces()
        # elif True == True: 
        elif command[0] == Commands.FINGERPRINT: 
            try:
                print('"Gimmer dini IP, jetzt wird gspottet..."')
                self.fingerprint(command[1], command[2])
            except IndexError as e: 
                Application.help(command[0])
            except struct.error as e: 
                print('')
        elif command[0] == Commands.TEST:
            try:
                Application.test(command[1], command[2])
            except IndexError as e:
                Application.help(command[0])
            except struct.error as e:
                pass
                # print(e)
        elif command[0] == Commands.IP:
            try:
                self.print_ip(command[1])
            except IndexError:
                Application.help(command[0])
            except struct.error:
                # print(e)
                pass
        elif command[0] == Commands.PORT:
            try:
                self.scan_ports(command[1], command[2], command[3], command[4])
            except IndexError as e:
                Application.help(command[0])

    def scan_ports(self, interface, target_ip, start_port, end_port):
        if interface in self.interfaces:
            try:
                socket.inet_aton(target_ip)
            except socket.error:
                print('Type a legal target ip address!')
                return
            ip = NetworkUtils.get_ip(interface)
            print('Starting port scan! From Port', start_port, ' to ', end_port)
            NetworkUtils.full_port_scan(ip, target_ip, int(start_port), int(end_port))
        else:
            print('Network interface not available!')
            print('Use interfaces command to get an available network interface.')

    @staticmethod
    def test(interface, target_ip):
        # print('executing...')
        ip = NetworkUtils.get_ip(interface)
        fingerprinter = FingerPrint(interface, ip, 'normal', 8080, target_ip, 8080)
        print("FINProbe-Test result: ", fingerprinter.execute_finprobe_test())

    def fingerprint(self, interface, to_ip):
        if interface in self.interfaces:
            try:
                socket.inet_aton(to_ip)
            except socket.error:
                print('Type a legal target ip address!')
                return
            ip = NetworkUtils.get_ip(interface)
            fingerprinter = FingerPrint(interface, ip, 'normal', 8080, to_ip, 8080)
            fingerprinter.execute_tests()
        else:
            print('Network interface not available!')
            print('Use interfaces command to get an available network interface.')

    def print_ip(self, interface):
        if interface in self.interfaces:
            ip = NetworkUtils.get_ip(interface)
            print('Your IP is: ' + ip, end='')
        else:
            print('Network interface not available!')
            print('Use interfaces command to get an available network interface.')

    def print_interfaces(self):
        self.interfaces = NetworkUtils.get_interfaces()
        for i, interface in enumerate(self.interfaces):
            print(i+1, end='') 
            print(': ', end='') 
            print(interface) 

    @staticmethod
    def intro():
        logo = ''' 
   ___ _                           ___                         ."".
  / __(_)_ __   __ _  ___ _ __    / __\ ___ _ __ _ __ _   _    |__|
 / _\ | | '_ \ / _` |/ _ \ '__|  /__\/// _ \ '__| '__| | | |   |  |
/ /   | | | | | (_| |  __/ |    / \/  \  __/ |  | |  | |_| |   |  |--.--.
\/    |_|_| |_|\__, |\___|_|    \_____/\___|_|  |_|   \__, |   |  | _|  | `|
               |___/                                  |___/    |  /` )  |  |
                                                               | /  /'--:__/
                   OS Fingerprinting Tool                      (  ' \      |
               ©2017 Arneli00, ItsYaBoiKikky                    \    `.   /
                  Type help to get started!                      |       |
                                                                 |       |
               '''
        print(logo) 
        print('Type help or help<command> for an extended documentation of the desired operation!') 

    @staticmethod
    def help(command=Commands.NONE):
        if command == Commands.NONE:
            print('There are following commands:')
            print('fingerprint, help, interfaces, port, ip, exit')
        elif command == Commands.HELP:
            print('There are following commands:')
            print('fingerprint, test, help, interfaces, port, ip, exit')
        elif command == Commands.FINGERPRINT:
            print('Find the desired network interface, by using the command interfaces beforehand!')
            print('Usage FINGERPRINT <interface> <target ip address> <port>')
        elif command == Commands.PORT:
            print('Scan target host for open ports! Scan from lower port range to upper range.')
            print('Usage PORT <target ip address> <from port> <to port>')
        elif command == Commands.IP:
            print('Print out your current ip on the desired network interface.')
            print("Usage: IP <interface>")
        elif command == Commands.INTERFACES:
            print('Prints all available network interfaces.')
            print("Usage: INTERFACES")

if __name__ == '__main__':
    if os.getuid() != 0:
        print('Please restart the application as superuser!')
    else:
        application = Application()
        application.run()
