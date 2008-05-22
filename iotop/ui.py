import curses
import errno
import optparse
import os
import pwd
import select
import struct
import sys

from iotop.data import find_uids, TaskStatsNetlink, ProcessList
from iotop.version import VERSION

#
# Utility functions for the UI
#

UNITS = ['B', 'K', 'M', 'G', 'T', 'P', 'E']

def human_bandwidth(size, duration):
    bw = size and float(size) / duration
    for i in xrange(len(UNITS) - 1, 0, -1):
        base = 1 << (10 * i)
        if 2 * base < size:
            res = '%.2f %s' % ((float(bw) / base), UNITS[i])
            break
    else:
        res = str(bw) + ' ' + UNITS[0]
    return res + '/s'

def human_stats(stats, duration):
    # Keep in sync with TaskStatsNetlink.members_offsets and
    # IOTopUI.get_data(self)
    def delay2percent(name): # delay in ns, duration in s
        return '%.2f %%' % min(99.99, stats[name][1] / (duration * 10000000.0))
    io_delay = delay2percent('blkio_delay_total')
    swapin_delay = delay2percent('swapin_delay_total')
    read_bytes = human_bandwidth(stats['read_bytes'][1], duration)
    written_bytes = stats['write_bytes'][1] - stats['cancelled_write_bytes'][1]
    written_bytes = max(0, written_bytes)
    write_bytes = human_bandwidth(written_bytes, duration)
    return io_delay, swapin_delay, read_bytes, write_bytes

#
# The UI
#

class IOTopUI(object):
    # key, reverse
    sorting_keys = [
        (lambda p: p.pid, False),
        (lambda p: p.user, False),
        (lambda p: p.stats['read_bytes'][1], True),
        (lambda p: p.stats['write_bytes'][1] -
                   p.stats['cancelled_write_bytes'][1], True),
        (lambda p: p.stats['swapin_delay_total'][1], True),
        # The default sorting (by I/O % time) should show processes doing
        # only writes, without waiting on them
        (lambda p: p.stats['blkio_delay_total'][1] or
                   int(not(not(p.stats['read_bytes'][1] or
                               p.stats['write_bytes'][1]))), True),
        (lambda p: p.get_cmdline(), False),
    ]

    def __init__(self, win, process_list, options):
        self.process_list = process_list
        self.options = options
        self.sorting_key = 5
        self.sorting_reverse = IOTopUI.sorting_keys[5][1]
        if not self.options.batch:
            self.win = win
            self.resize()
            try:
                curses.use_default_colors()
                curses.start_color()
                curses.curs_set(0)
            except curses.error:
                # This call can fail with misconfigured terminals, for example
                # TERM=xterm-color. This is harmless
                pass

    def resize(self):
        self.height, self.width = self.win.getmaxyx()

    def run(self):
        iterations = 0
        poll = select.poll()
        if not self.options.batch:
            poll.register(sys.stdin.fileno(), select.POLLIN|select.POLLPRI)
        while self.options.iterations is None or \
              iterations < self.options.iterations:
            total = self.process_list.refresh_processes()
            total_read, total_write = total
            self.refresh_display(total_read, total_write,
                                 self.process_list.duration)
            if self.options.iterations is not None:
                iterations += 1
                if iterations >= self.options.iterations:
                    break

            try:
                events = poll.poll(self.options.delay_seconds * 1000.0)
            except select.error, e:
                if e.args and e.args[0] == errno.EINTR:
                    events = 0
                else:
                    raise
            if not self.options.batch:
                self.resize()
            if events:
                key = self.win.getch()
                self.handle_key(key)

    def reverse_sorting(self):
        self.sorting_reverse = not self.sorting_reverse

    def adjust_sorting_key(self, delta):
        orig_sorting_key = self.sorting_key
        self.sorting_key += delta
        self.sorting_key = max(0, self.sorting_key)
        self.sorting_key = min(len(IOTopUI.sorting_keys) - 1, self.sorting_key)
        if orig_sorting_key != self.sorting_key:
            self.sorting_reverse = IOTopUI.sorting_keys[self.sorting_key][1]

    def handle_key(self, key):
        def toggle_only_io():
            self.options.only ^= True
        key_bindings = {
            ord('q'):
                lambda: sys.exit(0),
            ord('Q'):
                lambda: sys.exit(0),
            ord('r'):
                lambda: self.reverse_sorting(),
            ord('R'):
                lambda: self.reverse_sorting(),
            ord('o'):
                toggle_only_io,
            curses.KEY_LEFT:
                lambda: self.adjust_sorting_key(-1),
            curses.KEY_RIGHT:
                lambda: self.adjust_sorting_key(1),
            curses.KEY_HOME:
                lambda: self.adjust_sorting_key(-len(IOTopUI.sorting_keys)),
            curses.KEY_END:
                lambda: self.adjust_sorting_key(len(IOTopUI.sorting_keys))
        }

        action = key_bindings.get(key, lambda: None)
        action()

    def get_data(self):
        def format(p):
            stats = human_stats(p.stats, self.process_list.duration)
            io_delay, swapin_delay, read_bytes, write_bytes = stats
            line = '%5d %-8s %11s %11s %7s %7s ' % (p.pid, p.user[:8],
                                read_bytes, write_bytes, swapin_delay, io_delay)
            if self.options.batch:
                max_cmdline_length = 4096
            else:
                max_cmdline_length = self.width - len(line)
            line += p.get_cmdline()[:max_cmdline_length]
            return line

        def should_format(p):
            return not self.options.only or p.did_some_io()

        processes = self.process_list.processes.values()
        processes = filter(should_format, processes)
        key = IOTopUI.sorting_keys[self.sorting_key][0]
        processes.sort(key=key, reverse=self.sorting_reverse)
        if not self.options.batch:
            del processes[self.height - 2:]
        return map(format, processes)

    def refresh_display(self, total_read, total_write, duration):
        summary = 'Total DISK READ: %s | Total DISK WRITE: %s' % (
                                        human_bandwidth(total_read, duration),
                                        human_bandwidth(total_write, duration))
        titles = ['  PID', ' USER', '      DISK READ', '  DISK WRITE',
                  '   SWAPIN', '    IO', '    COMMAND']
        lines = self.get_data()
        if self.options.batch:
            print summary
            print ''.join(titles)
            for l in lines:
                print l
        else:
            self.win.erase()
            self.win.addstr(summary)
            self.win.hline(1, 0, ord(' ') | curses.A_REVERSE, self.width)
            for i in xrange(len(titles)):
                attr = curses.A_REVERSE
                title = titles[i]
                if i == self.sorting_key:
                    attr |= curses.A_BOLD
                    title += self.sorting_reverse and '>' or '<'
                self.win.addstr(title, attr)
            for i in xrange(len(lines)):
                self.win.insstr(i + 2, 0, lines[i])
            self.win.refresh()

def run_iotop(win, options):
    taskstats_connection = TaskStatsNetlink(options)
    process_list = ProcessList(taskstats_connection, options)
    ui = IOTopUI(win, process_list, options)
    ui.run()

#
# Main program
#

USAGE = '''%s [OPTIONS]

DISK READ and DISK WRITE are the block I/O bandwidth used during the sampling
period. SWAPIN and IO are the percentages of time the thread spent respectively
while swapping in and waiting on I/O more generally.
Controls: left and right arrows to change the sorting column, r to invert the
sorting order, o to toggle the --only option, q to quit, any other key to force
a refresh''' % sys.argv[0]

def main():
    parser = optparse.OptionParser(usage=USAGE, version='iotop ' + VERSION)
    parser.add_option('-o', '--only', action='store_true',
                      dest='only', default=False,
                      help='only show processes or threads actually doing I/O')
    parser.add_option('-b', '--batch', action='store_true', dest='batch',
                      help='non-interactive mode')
    parser.add_option('-n', '--iter', type='int', dest='iterations',
                      metavar='NUM',
                      help='number of iterations before ending [infinite]')
    parser.add_option('-d', '--delay', type='float', dest='delay_seconds',
                      help='delay between iterations [1 second]',
                      metavar='SEC', default=1)
    parser.add_option('-p', '--pid', type='int', dest='pids', action='append',
                      help='processes to monitor [all]', metavar='PID')
    parser.add_option('-u', '--user', type='str', dest='users', action='append',
                      help='users to monitor [all]', metavar='USER')
    parser.add_option('-P', '--processes', action='store_true',
                      dest='processes',
                      help='only show processes, not all threads')
    options, args = parser.parse_args()
    if args:
        parser.error('Unexpected arguments: ' + ' '.join(args))
    find_uids(options)
    options.pids = options.pids or []
    if options.batch:
        run_iotop(None, options)
    else:
        curses.wrapper(run_iotop, options)

