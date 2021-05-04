import os
import readline


class Faker:
    def __init__(self):
        self.default_ttl = 0
        self.default_sack = False
        self.running = True

    def run(self):
        self.intro()
        while self.running:
            self.run_command(input('>> '))

    def run_command(self, command):
        command = command.split(' ')
        if len(command) == 1 and command[0].lower() == 'exit':
            self.running = False

        if len(command) == 1 and command[0].lower() == 'default':
            self.set_ttl(self.default_ttl)
            self.set_sack(self.default_sack)

        elif len(command) == 2 and command[0].lower() == 'ttl':
            if command[1].isdigit():
                self.set_ttl(command[1])
            elif command[1].lower() == 'windows':
                self.set_ttl('128')
            elif command[1].lower() == 'bsd' or command[1].lower() == 'linux':
                self.set_ttl('64')
            elif command[1].lower() == 'ciscoios':
                self.set_ttl('255')
            elif command[1].lower() == 'macos':
                self.set_ttl('64')
                self.set_sack('0')
            else:
                print('You have to specify a number or the name of an operating system after set!')

        elif len(command) == 2 and command[0].lower() == 'sack':
            if command[1].isdigit() and int(command[1]) >= 0 and int(command[1]) <= 1:
                self.set_sack(command[1])
            elif command[1].lower() == 'windows':
                self.set_ttl(128)
            elif command[1].lower() == 'bsd' or command[1].lower() == 'linux':
                self.set_ttl(64)
            elif command[1].lower() == 'ciscoios':
                self.set_ttl(255)
            elif command[1].lower() == 'macos':
                self.set_ttl(64)
                self.set_sack(0)
            else:
                print('You have to specify a number between 0 and 1 after sack!')

        elif len(command) == 1 and command[0].lower() == 'exit':
            print('Bye bye')
            self.running = False

        else:
            print('Usage notes',
            '-Type "ttl <value|OS>" to change your ttl to an other value\n',
            '-Type "sack <0|1|OS>" to change your SACK-Option to an other value\n',
            '-Type "default" to restore your default settings\n',
            "-Available OS's: Windows, BSD, Linux, CiscoiOS and MacOS\n",
            'NOTE: To perform changes on your system, you may need to start this application as administrator\n',
            'NOTE: Your changes will be retained until the next boot process of your computer')

    def intro(self):
        print('Your current TTL-Value is: ', self.get_ttl(),
        'Your current SACK-Value is: ', self.get_sack(),
        '-Type "ttl <value|OS>" to change your ttl to an other value\n',
        '-Type "sack <0|1|OS>" to change your SACK-Option to an other value\n',
        '-Type "default" to restore your default settings\n',
        "-Available OS's: Windows, BSD, Linux, Cisco OS and Mac OS\n",
        'NOTE: To perform changes on your system, you may need to start this application as administrator\n',
        'NOTE: Your changes will be retained until the next boot process of your computer')

    def get_ttl(self):
        f = open('/proc/sys/net/ipv4/ip_default_ttl', 'r')
        ttl = f.read()
        f.close()
        self.default_ttl = ttl
        return ttl

    def get_sack(self):
        f = open('/proc/sys/net/ipv4/tcp_sack', 'r')
        sack = f.read()
        f.close()
        self.default_sack = sack
        return sack

    def set_ttl(self, ttl):
        try:
            f = open('/proc/sys/net/ipv4/ip_default_ttl', 'w')
            f.write(ttl)
            f.close()
            if ttl == self.default_ttl:
                print('TTL reset to ', ttl, ' successfully')
            else:
                print('TTL value changed to ', ttl, ' successfully')
        except:
            print('Failed to change the default-ttl of your computer!')

    def set_sack(self, sack):
        try:
            f = open('/proc/sys/net/ipv4/tcp_sack', 'w')
            f.write(sack)
            f.close()
            if sack == self.default_sack:
                print('SACK reset to ', sack, ' successfully')
            else:
                print('SACK value changed to ', sack, ' successfully')
        except:
            print('Failed to change the default-sack of your computer!')




if __name__ == "__main__":
    if os.getuid() != 0:
        print('Please restart the application as superuser!')
    else:
        faker = Faker()
        faker.run()
