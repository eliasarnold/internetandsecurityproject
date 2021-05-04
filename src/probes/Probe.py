from abc import ABC, abstractmethod


class Probe(ABC):
    def __init__(self, source_ip, source_port, target_ip, target_port, interface):
        self.target_ip = target_ip
        self.target_port = target_port
        self.source_ip = source_ip
        self.source_port = source_port
        self.interface = interface

    @abstractmethod
    def send(self, target_ip):
        raise NotImplementedError("Abstract method!")

    @abstractmethod
    def receive(self):
        raise NotImplementedError("Abstract method!")
