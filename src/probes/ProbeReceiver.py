import threading


class ProbeReceiver(threading.Thread):
    def __init__(self, probe, interface, queue):
        threading.Thread.__init__(self)
        self.probe = probe
        self.interface = interface
        self.queue = queue

    def run(self):
        result = self.probe.receive()
        self.queue.put(result)
        return
