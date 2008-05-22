import errno
import os
import pwd
import socket
import struct
import sys
import time

from netlink import Connection, NETLINK_GENERIC, U32Attr, NLM_F_REQUEST
from genetlink import Controller, GeNlMessage

#
# Check for requirements:
#   o Python >= 2.5 for AF_NETLINK sockets
#   o Linux >= 2.6.20 with I/O accounting
#
try:
    socket.NETLINK_ROUTE
    python25 = True
except AttributeError:
    python25 = False

ioaccounting = os.path.exists('/proc/self/io')

if not python25 or not ioaccounting:
    def boolean2string(boolean):
        return boolean and 'Found' or 'Not found'
    print 'Could not run iotop as some of the requirements are not met:'
    print '- Python >= 2.5 for AF_NETLINK support:', boolean2string(python25)
    print '- Linux >= 2.6.20 with I/O accounting support:', \
          boolean2string(ioaccounting)
    sys.exit(1)

#
# Netlink usage for taskstats
#

TASKSTATS_CMD_GET = 1
TASKSTATS_CMD_ATTR_PID = 1
TASKSTATS_CMD_ATTR_TGID = 2

class TaskStatsNetlink(object):
    # Keep in sync with human_stats(stats, duration) and pinfo.did_some_io()
    members_offsets = [
        ('blkio_delay_total', 40),
        ('swapin_delay_total', 56),
        ('read_bytes', 248),
        ('write_bytes', 256),
        ('cancelled_write_bytes', 264)
    ]

    def __init__(self, options):
        self.options = options
        self.connection = Connection(NETLINK_GENERIC)
        controller = Controller(self.connection)
        self.family_id = controller.get_family_id('TASKSTATS')

    def get_task_stats(self, pid):
        if self.options.processes:
            attr = TASKSTATS_CMD_ATTR_TGID
        else:
            attr = TASKSTATS_CMD_ATTR_PID
        request = GeNlMessage(self.family_id, cmd=TASKSTATS_CMD_GET,
                              attrs=[U32Attr(attr, pid)],
                              flags=NLM_F_REQUEST)
        request.send(self.connection)
        try:
            reply = self.connection.recv()
        except OSError, e:
            if e.errno == errno.ESRCH:
                # OSError: Netlink error: No such process (3)
                return
            raise
        if len(reply.payload) < 292:
            # Short reply
            return
        reply_data = reply.payload[20:]

        reply_length, reply_type = struct.unpack('HH', reply.payload[4:8])
        reply_version = struct.unpack('H', reply.payload[20:22])[0]
        assert reply_length >= 288
        assert reply_type == attr + 3
        assert reply_version >= 4

        res = {}
        for name, offset in TaskStatsNetlink.members_offsets:
            data = reply_data[offset: offset + 8]
            res[name] = struct.unpack('Q', data)[0]

        return res

#
# PIDs manipulations
#

def find_uids(options):
    options.uids = []
    error = False
    for u in options.users or []:
        try:
            uid = int(u)
        except ValueError:
            try:
                passwd = pwd.getpwnam(u)
            except KeyError:
                print >> sys.stderr, 'Unknown user:', u
                error = True
            else:
                uid = passwd.pw_uid
        if not error:
            options.uids.append(uid)
    if error:
        sys.exit(1)

class pinfo(object):
    def __init__(self, pid, options):
        self.mark = False
        self.pid = pid
        self.stats = {}
        for name, offset in TaskStatsNetlink.members_offsets:
            self.stats[name] = (0, 0) # Total, Delta
        self.parse_status('/proc/%d/status' % pid, options)

    def check_if_valid(self, uid, options):
        self.valid = options.pids or not options.uids or uid in options.uids

    def parse_status(self, path, options):
        for line in open(path):
            if line.startswith('Name:'):
                # Name kernel threads
                self.name = '[' + line.split()[1].strip() + ']'
            elif line.startswith('Uid:'):
                uid = int(line.split()[1])
                # We check monitored PIDs only here
                self.check_if_valid(uid, options)
                try:
                    self.user = pwd.getpwuid(uid).pw_name
                except KeyError:
                    self.user = str(uid)
                break

    def add_stats(self, stats):
        self.stats_timestamp = time.time()
        for name, value in stats.iteritems():
            prev_value = self.stats[name][0]
            self.stats[name] = (value, value - prev_value)

    def get_cmdline(self):
        # A process may exec, so we must always reread its cmdline
        try:
            proc_cmdline = open('/proc/%d/cmdline' % self.pid)
            cmdline = proc_cmdline.read(4096)
        except IOError:
            return '{no such process}'
        parts = cmdline.split('\0')
        if parts[0].startswith('/'):
            first_command_char = parts[0].rfind('/') + 1
            parts[0] = parts[0][first_command_char:]
        cmdline = ' '.join(parts).strip()
        return cmdline.encode('string_escape') or self.name

    def did_some_io(self):
        for name in self.stats:
            if self.stats[name][1]:
                return True

        return False

class ProcessList(object):
    def __init__(self, taskstats_connection, options):
        # {pid: pinfo}
        self.processes = {}
        self.taskstats_connection = taskstats_connection
        self.options = options
        self.timestamp = time.time()

        # A first time as we are interested in the delta
        self.update_process_counts()

    def get_process(self, pid):
        process = self.processes.get(pid, None)
        if not process:
            try:
                process = pinfo(pid, self.options)
            except IOError:
                # IOError: [Errno 2] No such file or directory: '/proc/...'
                return
            if not process.valid:
                return
            self.processes[pid] = process
        return process

    def list_pids(self, tgid):
        if self.options.processes or self.options.pids:
            return [tgid]
        try:
            return map(int, os.listdir('/proc/%d/task' % tgid))
        except OSError:
            return []

    def update_process_counts(self):
        new_timestamp = time.time()
        self.duration = new_timestamp - self.timestamp
        self.timestamp = new_timestamp
        total_read = total_write = 0
        tgids = self.options.pids or [int(tgid) for tgid in os.listdir('/proc')
                                      if '0' <= tgid[0] and tgid[0] <= '9']
        for tgid in tgids:
            for pid in self.list_pids(tgid):
                process = self.get_process(pid)
                if process:
                    stats = self.taskstats_connection.get_task_stats(pid)
                    if stats:
                        process.mark = False
                        process.add_stats(stats)
                        total_read += process.stats['read_bytes'][1]
                        total_write += process.stats['write_bytes'][1]
        return total_read, total_write

    def refresh_processes(self):
        for process in self.processes.values():
            process.mark = True
        total_read_and_write = self.update_process_counts()
        to_delete = []
        for pid, process in self.processes.iteritems():
            if process.mark:
                to_delete.append(pid)
        for pid in to_delete:
            del self.processes[pid]
        return total_read_and_write

