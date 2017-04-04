#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import argparse
import locale
import logging
import re
import sys

from collections import deque, namedtuple
from datetime import datetime, timedelta
from os import path

from heap import Heap

logger = None

def configure_logging(level):
    global logger

    logger = logging.getLogger('process_log')
    logger.setLevel(level)

    ch = logging.StreamHandler()
    ch.setLevel(level)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

AccessLogEntry = namedtuple('AcessLogEntry',
                            ['host', 'ts', 'resource', 'status', 'bytes', 'raw'])

class AccessLogParser(object):
    '''A parser for individual lines from the access log.'''

    time_format = '%d/%b/%Y:%H:%M:%S -0400'

    def __init__(self):
        self._re = re.compile(r'''
            ^(?P<host>[^\s]+)\s+        # 208.271.69.50
            -\s+                        # -
            -\s+                        # -
            \[(?P<ts>[^]]+)\]\s+        # [01/Aug/1995:00:00:02 -0400]
            "[^\s]+\s+                  # "POST
             (?P<resource>[^\s]+)       # /login
             [^"]*"\s+                  # HTTP/1.0"
            (?P<status>\d+)\s+          # 401
            (?P<bytes>-|\d+)$           # 1420
            ''', re.VERBOSE)

    def _parse_timestamp(self, ts):
        '''Parse `ts' into a `datetime' object'''
        return datetime.strptime(ts, self.time_format)

    def _parse_bytes(self, bytes):
        '''Parse the number of bytes sent by the server for a request.
        `-' is treated as zero.
        '''
        if bytes == '-':
            return 0
        else:
            return int(bytes)

    def parse_line(self, line):
        '''Parse one access log line into a `AccessLogEntry' object.
        If the line cannot be parsed, return None.
        '''
        match = self._re.match(line)
        if match is None:
            return None

        d = match.groupdict()

        try:
            host = d['host']
            ts = self._parse_timestamp(d['ts'])
            resource = d['resource']
            status = int(d['status'])
            bytes = self._parse_bytes(d['bytes'])
        except:
            _, e, _ = sys.exc_info()
            logger.debug('Exception while parsing \'%s\': %s' % (line, e))
            return None

        return AccessLogEntry(host=host, ts=ts, resource=resource,
                              status=status, bytes=bytes, raw=line)

class FileReader(object):
    '''A reader object that streams the content of a file line by line.
    The file is read incrementally.
    '''

    def __init__(self, path):
        '''Initialize a reader object for a file at `path'.'''

        self._file = open(path, 'r', buffering=1024 * 1024)

    def __del__(self):
        try:
            self._file.close()
        except:
            pass

    def stream_lines(self):
        '''Return a generator that goes through all the lines in the file.
        Trailing whitespaces a stripped.
        When end of file is reached, return None.
        '''

        while True:
            line = self._file.readline()
            if not line:
                self._file.close()
                return

            yield line.rstrip()

class EventWindow(object):
    '''An object that keeps track of the events (timestamps) that fall into a
    certain time window. When the new events are added, the old ones get expired
    when needed.
    '''

    def __init__(self, delta, *args):
        '''Initialize an `EventWindow' where the window size is `delta'.'''
        self._delta = delta
        self._events = deque()

        self._start = None
        self._end = None

        for ts in args:
            self.add_event(ts)

    def __repr__(self):
        return 'EventWindow(%s, *%s)' % (self._delta, list(self._events))

    def first(self):
        '''Return the first event in the window.'''
        return self._start

    def pop_first(self):
        '''Return and remove the first event in the window.
        Return None if there are no events.
        '''
        if self.is_empty():
            return None

        event = self._events.popleft()
        if self.is_empty():
            self._start = None
            self._end = None
        else:
            self._start = self._events[0]

        return event

    def last(self):
        '''Return the last event in the window.
        Return None if there are no events.
        '''
        if self.is_empty():
            return None

        return self._events[-1]

    def count(self):
        '''Return the number of events in the window.'''
        return len(self._events)

    def will_overflow(self, ts):
        '''Return True if adding a new event at `ts' will result in some old
        events being dropped.
        '''
        return self._end is not None and ts > self._end

    def is_empty(self):
        '''Check if the window is empty.'''
        return self.count() == 0

    def add_event(self, ts):
        '''Add a new event to the end of the window.
        Expire outdated events if needed.
        '''
        if self._start is None:
            self._start = ts
            self._end = ts + self._delta

        self._events.append(ts)
        if ts > self._end:
            self._adjust_start(ts)

    def expire(self, ts):
        '''Expire the outdated events as of `ts'.
        No new events are added to the window.
        '''
        self._adjust_start(ts)

    def _adjust_start(self, ts):
        while True:
            start = self._events.popleft()
            end = start + self._delta

            if ts <= end:
                self._start = start
                self._end = end
                self._events.appendleft(start)
                break

            if self.is_empty():
                self._start = None
                self._end = None
                break

class TopCounter(object):
    '''An object that keeps track of the number of times different items have
    been seen and supports efficient way of getting a fixed number of most
    frequent items.
    '''

    class Pair(object):
        '''A pair of an item and a count that shows how many time the item
        has been seen.
        '''

        def __init__(self, item, count):
            self.item = item
            self.count = count

        def __eq__(self, other):
            return self.count == other.count and self.item == other.item

        def __lt__(self, other):
            if self.count == other.count:
                return self.item > other.item

            return self.count < other.count

        def __le__(self, other):
            return self < other or self == other

        def __repr__(self):
            return 'Pair(%s, %d)' % (self.item, self.count)

        def __hash__(self):
            return hash((self.item, self.count))

    def __init__(self, num_top):
        '''Initialize a `TopCounter' object that keeps track of `num_top' most
        frequent items.
        '''
        self._counters = {}
        self._num_top = num_top

        self._top_heap = Heap()

    def _get_count(self, item):
        '''Return number of time `item' has been seen.'''
        return self._counters.get(item, 0)

    def inc(self, item, by=1):
        '''Increment the number of times `item' has been seen by `by'.'''
        old_count = self._get_count(item)
        new_count = old_count + by

        self._counters[item] = new_count
        self._update_heap(item, old_count, new_count)

    def set(self, item, new_count):
        '''Set the number of times `item' has been seen.'''
        old_count = self._get_count(item)
        self._counters[item] = new_count
        self._update_heap(item, old_count, new_count)

    def _update_heap(self, item, old_count, new_count):
        new_pair = TopCounter.Pair(item, new_count)
        old_pair = TopCounter.Pair(item, old_count)

        if old_pair in self._top_heap:
            self._top_heap.replace(old_pair, new_pair)
            return

        if self._top_heap.size() < self._num_top:
            self._top_heap.push(new_pair)
            return

        if new_pair < self._top_heap.min():
            # only if our new pair is larger than current smallest one does it
            # make sense to insert it into the heap
            return

        self._top_heap.replace_min(new_pair)

    def get_top(self):
        '''Get the most frequent items. Returns a list of tuples where the first
        element is the item, the second -- the number of times it's been seen.
        '''
        items = [(p.item, p.count) for p in self._top_heap]
        items.reverse()
        return items

class LoginTracker(object):
    '''Keeps track of all the failed login attempts and blocked hosts.
    Based on this provides a guidance if a subsequent event needs to be blocked.
    '''

    class HostTimestamp(object):
        def __init__(self, host, ts):
            self.host = host
            self.ts = ts

        def __eq__(self, other):
            return self.host == other.host and self.ts == other.ts

        def __lt__(self, other):
            return (self.ts, self.host) < (other.ts, other.host)

        def __le__(self, other):
            return self == other or self < other

        def __hash__(self):
            return hash((self.ts, self.host))

        def __repr__(self):
            return '%s(%s, %s)' % (type(self).__name__, repr(self.host), repr(self.ts))

    class FailedLogin(HostTimestamp):
        pass

    class UnblockTimestamp(HostTimestamp):
        pass

    def __init__(self, delta, block_delay, max_attempts):
        '''Initialize the tracker. If more than `max_attempts' failed logins
        happen during `delta' time window, block the host for `block_delay'
        period of time.
        '''
        self._max_attempts = max_attempts
        self._delta = delta
        self._block_delay = block_delay

        self._failed_logins = {}
        self._failed_logins_heap = Heap()

        self._blocked_hosts = set()
        self._unblock_timestamps = Heap()

    def _is_login(self, entry):
        return entry.resource == '/login'

    def _is_unauthorized(self, entry):
        return entry.status == 401

    def _add_failed_login(self, host, ts):
        login = LoginTracker.FailedLogin(host, ts)

        if host not in self._failed_logins:
            self._failed_logins[host] = EventWindow(delta=self._delta)
            self._failed_logins_heap.push(login)

        self._failed_logins[host].add_event(login.ts)

    def _remove_failed_logins(self, host):
        logins = self._failed_logins[host]
        login = LoginTracker.FailedLogin(host, logins.first())

        self._failed_logins_heap.remove(login)
        del self._failed_logins[host]

    def _expire_failed_logins(self, current_ts):
        heap = self._failed_logins_heap

        while not heap.is_empty() and heap.min().ts + self._block_delay < current_ts:
            login = heap.pop()

            host = login.host
            host_logins = self._failed_logins[host]
            host_logins.expire(current_ts)

            if host_logins.count() == 0:
                del self._failed_logins[host]
                continue

            heap.push(LoginTracker.FailedLogin(host, host_logins.first()))

    def _should_block(self, host):
        logins = self._failed_logins.get(host)
        return logins is not None and logins.count() >= self._max_attempts

    def _block(self, host, current_ts):
        self._remove_failed_logins(host)
        self._blocked_hosts.add(host)

        unblock = LoginTracker.UnblockTimestamp(host, current_ts + self._block_delay)
        self._unblock_timestamps.push(unblock)

    def _is_blocked(self, host):
        return host in self._blocked_hosts

    def _expire_blocked(self, current_ts):
        heap = self._unblock_timestamps

        while not heap.is_empty() and heap.min().ts < current_ts:
            host = heap.pop().host
            self._blocked_hosts.remove(host)

    def handle_entry(self, entry):
        '''For a given request return True if it needs to be blocked.'''
        host = entry.host
        current_ts = entry.ts

        # first expire all the stale failed logins
        self._expire_failed_logins(current_ts)
        # unblock the hosts that don't need to be blocked anymore
        self._expire_blocked(current_ts)

        # if we still find that the host is blocked, tell the caller to block
        if self._is_blocked(host):
            return True

        # the host is not blocked
        #
        # if the request is not login, we are done
        if not self._is_login(entry):
            return False

        # if it's a successful login, we remove previous failed logins (if any)
        if not self._is_unauthorized(entry):
            if host in self._failed_logins:
                self._remove_failed_logins(host)

            return False

        # if it's a failed login, add it to the list
        self._add_failed_login(host, current_ts)

        # do we need to block the host?
        if self._should_block(host):
            # if yes, block the host
            self._block(host, current_ts)

        return False

class BusyHoursTracker(object):
    '''Keeps track of the busiest hours on the server.'''

    second = timedelta(seconds=1)

    def __init__(self, top, delta):
        '''Keep track of `top' busiest periods of time that last `delta'.'''
        self._top = TopCounter(top)
        self._window = EventWindow(delta=delta)
        self._delta = delta

    def get_top(self):
        '''Get the busiest hours.'''
        self._finalize()
        return self._top.get_top()

    def _format_time(self, ts):
        return datetime.strftime(ts, AccessLogParser.time_format)

    def update(self, entry):
        '''Update the stats according to the access log entry.'''
        ts = entry.ts

        self._update(ts)
        self._window.add_event(ts)

    def _update(self, ts):
        # we don't do anything until we've seen enough events to overflow
        # `delta'
        while self._window.will_overflow(ts):
            # update information according to each expired event
            self._update_one()

    def _update_one(self):
        count = self._window.count()
        start = self._window.pop_first()

        while True:
            end = self._window.first()
            if end != start:
                break

            self._window.pop_first()

        self._top.set(self._format_time(start), count)
        if end is not None:
            count = self._window.count()
            start += self.second

            while start <= end:
                self._top.set(self._format_time(start), count)
                start += self.second

    def _finalize(self):
        while not self._window.is_empty():
            self._update_one()

class AccessLogAnalyzer(object):
    '''Access log analyzer.'''

    def __init__(self, line_source, results_sink):
        '''Initialize access log analyzer. Get the access log lines
        from `line_source'. Report the results to `results_sink'.
        '''

        self._line_source = line_source
        self._log_parser = AccessLogParser()
        self._top_hosts = TopCounter(10)
        self._top_resources = TopCounter(10)

        self._busy_hours = BusyHoursTracker(top=10, delta=timedelta(minutes=60))

        self._login_tracker = LoginTracker(delta=timedelta(seconds=20),
                                           block_delay=timedelta(minutes=5),
                                           max_attempts=3)

        self._results_sink = results_sink

    def process_log(self):
        '''Process the access log file and report the results to the sink.'''

        for line in self._line_source.stream_lines():
            entry = self._log_parser.parse_line(line)

            if entry is None:
                logger.info('Invalid access log entry entry: \'%s\'' % line)
                continue

            self._top_hosts.inc(entry.host)
            self._top_resources.inc(entry.resource, by=entry.bytes)
            self._busy_hours.update(entry)

            must_block = self._login_tracker.handle_entry(entry)
            if must_block:
                self._results_sink.note_blocked(entry.raw)

        self._results_sink.note_top_hosts(self._top_hosts.get_top())
        self._results_sink.note_top_resources(self._top_resources.get_top())
        self._results_sink.note_top_hours(self._busy_hours.get_top())

class ResultsSink(object):
    '''Called in by `AccessLogAnalyzer' when the results are ready.
    Stores the results to appropriate files on disk.
    '''

    def __init__(self, output_dir):
        '''Initialze the sink. Store the results to `output_dir' directory.'''
        self._output_dir = output_dir

    def __del__(self):
        self._close()

    def __enter__(self):
        self._blocked = self._open('blocked.txt')
        return self

    def __exit__(self, *args):
        self._close()

    def _open(self, name):
        return open(path.join(self._output_dir, name), 'w')

    def _close(self):
        try:
            self._blocked.close()
        except:
            pass

    def note_top_hosts(self, top_hosts):
        '''Store the most active hosts.'''
        with self._open('hosts.txt') as f:
            for host, count in top_hosts:
                f.write('%s,%d\n' % (host, count))

    def note_top_resources(self, top_resources):
        '''Store the resources that used most bandwidth.'''
        with self._open('resources.txt') as f:
            for resource, _ in top_resources:
                f.write(resource)
                f.write('\n')

    def note_top_hours(self, top_hours):
        '''Store the busiest hours.'''
        with self._open('hours.txt') as f:
            for hour, count in top_hours:
                f.write('%s,%d\n' % (hour, count))

    def note_blocked(self, log_line):
        '''Store one blocked request to the corresponding file. Shoud be called
        repeatedly until there are no more blocked requests.
        '''
        self._blocked.write(log_line)
        self._blocked.write('\n')

def main():
    locale.setlocale(locale.LC_ALL, 'C')

    parser = argparse.ArgumentParser(description='Access log analyzer')
    parser.add_argument('--input', dest='input',
                        default='log.txt',
                        help='path to the input file')
    parser.add_argument('--output-directory', dest='output_dir',
                        default='.',
                        help='path to the output directory')
    parser.add_argument('--debug', dest='debug', action='store_true',
                        default=False,
                        help='enable debug mode')
    args = parser.parse_args()

    loglevel = logging.DEBUG if args.debug else logging.ERROR
    configure_logging(loglevel)

    source = FileReader(args.input)

    with ResultsSink(args.output_dir) as sink:
        analyzer = AccessLogAnalyzer(source, sink)
        analyzer.process_log()

if __name__ == '__main__':
        main()
