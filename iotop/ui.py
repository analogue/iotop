import curses
import errno
import locale
import optparse
import os
import pwd
import select
import struct
import sys
import time

from iotop.data import find_uids, TaskStatsNetlink, ProcessList
from iotop.version import VERSION

#
# Utility functions for the UI
#

UNITS = ['B', 'K', 'M', 'G', 'T', 'P', 'E']

def human_size(size):
    for i in xrange(len(UNITS) - 1, 0, -1):
        base = 1 << (10 * i)
        if 2 * base < size:
            break
    else:
        i = 0
        base = 1
    return '%.2f %s' % ((float(size) / base), UNITS[i])

def format_size(options, bytes):
    if options.kilobytes:
        return '%.2f K' % (bytes / 1024.0)
    return human_size(bytes)

def format_bandwidth(options, size, duration):
    return format_size(options, size and float(size) / duration) + '/s'

def format_stats(options, process, duration):
    # Keep in sync with TaskStatsNetlink.members_offsets and
    # IOTopUI.get_data(self)
    def delay2percent(delay): # delay in ns, duration in s
        return '%.2f %%' % min(99.99, delay / (duration * 10000000.0))
    if options.accumulated:
        stats = process.stats_accum
        display_format = lambda size, duration: format_size(options, size)
        duration = time.time() - process.stats_accum_timestamp
    else:
        stats = process.stats_delta
        display_format = lambda size, duration: format_bandwidth(
                                                        options, size, duration)
    io_delay = delay2percent(stats.blkio_delay_total)
    swapin_delay = delay2percent(stats.swapin_delay_total)
    read_bytes = display_format(stats.read_bytes, duration)
    written_bytes = stats.write_bytes - stats.cancelled_write_bytes
    written_bytes = max(0, written_bytes)
    write_bytes = display_format(written_bytes, duration)
    return io_delay, swapin_delay, read_bytes, write_bytes

#
# The UI
#

class IOTopUI(object):
    # key, reverse
    sorting_keys = [
        (lambda p: p.pid, False),
        (lambda p: p.ioprio_sort_key(), False),
        (lambda p: p.get_user(), False),
        (lambda p: p.stats_delta.read_bytes, True),
        (lambda p: p.stats_delta.write_bytes -
                   p.stats_delta.cancelled_write_bytes, True),
        (lambda p: p.stats_delta.swapin_delay_total, True),
        # The default sorting (by I/O % time) should show processes doing
        # only writes, without waiting on them
        (lambda p: p.stats_delta.blkio_delay_total or
                   int(not(not(p.stats_delta.read_bytes or
                               p.stats_delta.write_bytes))), True),
        (lambda p: p.get_cmdline(), False),
    ]

    def __init__(self, win, process_list, options):
        self.process_list = process_list
        self.options = options
        self.sorting_key = 6
        self.sorting_reverse = IOTopUI.sorting_keys[self.sorting_key][1]
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
            self.refresh_display(iterations == 0, total_read, total_write,
                                 self.process_list.duration)
            if self.options.iterations is not None:
                iterations += 1
                if iterations >= self.options.iterations:
                    break
            elif iterations == 0:
                iterations = 1

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
        def toggle_accumulated():
            self.options.accumulated ^= True
            self.process_list.clear()
        def toggle_only_io():
            self.options.only ^= True
        def toggle_processes():
            self.options.processes ^= True
            self.process_list.clear()
            self.process_list.refresh_processes()
        key_bindings = {
            ord('q'):
                lambda: sys.exit(0),
            ord('Q'):
                lambda: sys.exit(0),
            ord('r'):
                lambda: self.reverse_sorting(),
            ord('R'):
                lambda: self.reverse_sorting(),
            ord('a'):
                toggle_accumulated,
            ord('A'):
                toggle_accumulated,
            ord('o'):
                toggle_only_io,
            ord('O'):
                toggle_only_io,
            ord('p'):
                toggle_processes,
            ord('P'):
                toggle_processes,
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
            stats = format_stats(self.options, p, self.process_list.duration)
            io_delay, swapin_delay, read_bytes, write_bytes = stats
            line = '%5d %4s %-8s %11s %11s %7s %7s ' % (
                p.pid, p.get_ioprio(), p.get_user()[:8], read_bytes,
                write_bytes, swapin_delay, io_delay)
            line += p.get_cmdline()
            if not self.options.batch:
                line = line[:self.width - 1]
            return line

        def should_format(p):
            return not self.options.only or p.did_some_io()

        processes = filter(should_format, self.process_list.processes.values())
        key = IOTopUI.sorting_keys[self.sorting_key][0]
        processes.sort(key=key, reverse=self.sorting_reverse)
        if not self.options.batch:
            del processes[self.height - 2:]
        return map(format, processes)

    def refresh_display(self, first_time, total_read, total_write, duration):
        summary = 'Total DISK READ: %s | Total DISK WRITE: %s' % (
                          format_bandwidth(self.options, total_read, duration),
                          format_bandwidth(self.options, total_write, duration))
        if self.options.processes:
            pid = '  PID'
        else:
            pid = '  TID'
        titles = [pid, '  PRIO', '  USER', '     DISK READ', '  DISK WRITE',
                  '  SWAPIN', '      IO', '    COMMAND']
        lines = self.get_data()
        if self.options.time:
            titles = ['    TIME'] + titles
            current_time = time.strftime('%H:%M:%S ')
            lines = [current_time + l for l in lines]
        if self.options.batch:
            if self.options.quiet <= 2:
                print summary
                if self.options.quiet <= int(first_time):
                    print ''.join(titles)
            for l in lines:
                print l
            sys.stdout.flush()
        else:
            self.win.erase()
            self.win.addstr(summary)
            self.win.hline(1, 0, ord(' ') | curses.A_REVERSE, self.width)
            for i in xrange(len(titles)):
                attr = curses.A_REVERSE
                title = titles[i]
                if i == self.sorting_key:
                    title = title[1:]
                if i == self.sorting_key:
                    attr |= curses.A_BOLD
                    title += self.sorting_reverse and '>' or '<'
                self.win.addstr(title, attr)
            for i in xrange(len(lines)):
                try:
                    self.win.addstr(i + 2, 0, lines[i].encode('utf-8'))
                except curses.error:
                    exc_type, value, traceback = sys.exc_info()
                    value = '%s win:%s i:%d line:%s' % \
                                       (value, self.win.getmaxyx(), i, lines[i])
                    value = str(value).encode('string_escape')
                    raise exc_type, value, traceback
            self.win.refresh()

def run_iotop_window(win, options):
    taskstats_connection = TaskStatsNetlink(options)
    process_list = ProcessList(taskstats_connection, options)
    ui = IOTopUI(win, process_list, options)
    ui.run()

def run_iotop(options):
    if options.batch:
        return run_iotop_window(None, options)
    else:
        return curses.wrapper(run_iotop_window, options)

#
# Profiling
#

def _profile(continuation):
    prof_file = 'iotop.prof'
    try:
        import cProfile
        import pstats
        print 'Profiling using cProfile'
        cProfile.runctx('continuation()', globals(), locals(), prof_file)
        stats = pstats.Stats(prof_file)
    except ImportError:
        import hotshot
        import hotshot.stats
        prof = hotshot.Profile(prof_file, lineevents=1)
        print 'Profiling using hotshot'
        prof.runcall(continuation)
        prof.close()
        stats = hotshot.stats.load(prof_file)
    stats.strip_dirs()
    stats.sort_stats('time', 'calls')
    stats.print_stats(50)
    stats.print_callees(50)
    os.remove(prof_file)

#
# Main program
#

USAGE = '''%s [OPTIONS]

DISK READ and DISK WRITE are the block I/O bandwidth used during the sampling
period. SWAPIN and IO are the percentages of time the thread spent respectively
while swapping in and waiting on I/O more generally. PRIO is the I/O priority at
which the thread is running (set using the ionice command).

Controls: left and right arrows to change the sorting column, r to invert the
sorting order, o to toggle the --only option, p to toggle the --processes
option, a to toggle the --accumulated option, q to quit, any other key to force a refresh.''' % sys.argv[0]

def main():
    locale.setlocale(locale.LC_ALL, '')
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
                      help='processes/threads to monitor [all]', metavar='PID')
    parser.add_option('-u', '--user', type='str', dest='users', action='append',
                      help='users to monitor [all]', metavar='USER')
    parser.add_option('-P', '--processes', action='store_true',
                      dest='processes', default=False,
                      help='only show processes, not all threads')
    parser.add_option('-a', '--accumulated', action='store_true',
                      dest='accumulated', default=False,
                      help='show accumulated I/O instead of bandwidth')
    parser.add_option('-k', '--kilobytes', action='store_true',
                      dest='kilobytes', default=False,
                      help='use kilobytes instead of a human friendly unit')
    parser.add_option('-t', '--time', action='store_true', dest='time',
                      help='add a timestamp on each line (implies --batch)')
    parser.add_option('-q', '--quiet', action='count', dest='quiet',
                      help='suppress some lines of header (implies --batch)')
    parser.add_option('--profile', action='store_true', dest='profile',
                      default=False, help=optparse.SUPPRESS_HELP)

    options, args = parser.parse_args()
    if args:
        parser.error('Unexpected arguments: ' + ' '.join(args))
    find_uids(options)
    options.pids = options.pids or []
    options.batch = options.batch or options.time or options.quiet

    main_loop = lambda: run_iotop(options)

    if options.profile:
        def safe_main_loop():
            try:
                main_loop()
            except:
                pass
        _profile(safe_main_loop)
    else:
        main_loop()

