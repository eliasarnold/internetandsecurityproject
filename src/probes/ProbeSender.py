import socket, struct, threading, time
from enum import IntEnum
from NetworkUtils import *


class ProbeSender(threading.Thread):
    def __init__(self, probe, source_ip, source_port, target_ip, target_port):
        threading.Thread.__init__(self)
        self.probe = probe
        self.source_port = source_port
        self.source_ip = source_ip
        self.target_port = target_port
        self.target_ip = target_ip

    def run(self):
        time.sleep(1)
        self.probe.send(self.target_ip)

    def change_probe(self, new_probe):
        self.probe = new_probe

