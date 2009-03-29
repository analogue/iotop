import os

class VmStat(object):
    def __init__(self):
        self.vmstat_file = open('/proc/vmstat')
        self.vmstat = self.read()

    def read(self):
        def extract(line):
            return int(line.split()[1]) * 1024

        for line in self.vmstat_file:
            if line.startswith('pgpgin '):
                pgpgin = extract(line)
                break

        for line in self.vmstat_file:
            if line.startswith('pgpgout '):
                pgpgout = extract(line)
                break

        self.vmstat_file.seek(0)
        return pgpgin, pgpgout

    def delta(self):
        now = self.read()
        delta = now[0] - self.vmstat[0], now[1] - self.vmstat[1]
        self.vmstat = now
        return delta

