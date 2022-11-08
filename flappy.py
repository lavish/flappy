#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Run exploits against selected targets and collect flags."""

# pip install --user requests iptools regex

import os
import sys
import signal
import socket
import logging
import argparse
import threading
import subprocess
from queue import Empty, Queue
from time import sleep, time

import iptools
import requests
# using regex for additional features over standard re
import regex as re

# ================================================================================
# CONFIG.
# Edit the settings below and adjust the get_flagids_service and submit_flags 
# functions. Alternative implementations are provided as _get_flagids_service and
# _submit_flags. You may also want to customize the init_teams function, for
# instance to hardcode a list reachable Team instances.
# ================================================================================

# your team token for flag submission/gameserver interaction, if needed
TEAM_TOKEN = 'h4ck7h3pl4n37'
# compiled regular expression matching a flag
FLAG_PATTERN = re.compile(b'FLAG\{[a-zA-Z0-9]{32}\}')
# duration of a round, in seconds. Divide it by 2 to attack with higher frequency!
ROUND_DURATION = 90
# endpoint serving the JSON with flag ids, use the IP address in case of DNS issues
FLAGID_URL = 'http://10.0.0.1/api/flag_id'
# flag submission URL for HTTP-based systems
FLAG_SUBMISSION_URL = 'http://10.0.0.1/submit'
# flag submission server host and port for socket-based systems
FLAG_SUBMISSION_HOST = '10.0.13.37'
FLAG_SUBMISSION_PORT = 1337
# maximum timeout for interactions with the gameserver
BASE_TIMEOUT = 5
# logging format
LOGGING_FMT = '[%(name)s %(levelname)s] %(message)s'

# ================================================================================
# /CONFIG
# ================================================================================


__author__ = "Marco Squarcina"
__license__ = "MIT"
__copyright__ = "Copyright 2014-2022"
__maintainer__ = "Marco Squarcina"
__email__ = "marco.squarcina@tuwien.ac.at"

# global variables

# custom logger
logger = logging.getLogger('attack')
# task queue: each task is an ip to be processed
tasks_noprio = Queue()
# print the output of each exploit if set to True
stdout_print = False
# disable reporting errors if set to True
stderr_print = False
# number of times it's needed to press ctrl-c before brutally dying
death_countdown = 5
# global dictionary of the teams, where the key is the team ip and the value a Team instance
teams = dict()
# lock used to modify the teams dictionary
lock = threading.Lock()

_colors = dict(black=30, red=31, green=32, yellow=33,
               blue=34, magenta=35, cyan=36, lgray=37,
               dgray=90, lred=91, lgreen=92, lyellow=93,
               lblue=94, lmagenta=95, lcyan=96, white=97)


# classes

class _AnsiColorizer(object):
    """
    A colorizer is an object that loosely wraps around a stream, allowing
    callers to write text to the stream in a particular color.

    Colorizer classes must implement C{supported()} and C{write(text, color)}.
    """

    def __init__(self, stream):
        self.stream = stream

    @classmethod
    def supported(cls, stream=sys.stdout):
        """
        A class method that returns True if the current platform supports
        coloring terminal output using this method. Returns False otherwise.
        """

        if not stream.isatty():
            return False  # auto color only on TTYs
        try:
            import curses
        except ImportError:
            return False
        else:
            try:
                try:
                    return curses.tigetnum("colors") > 2
                except curses.error:
                    curses.setupterm()
                    return curses.tigetnum("colors") > 2
            except:
                raise
                # guess false in case of error
                return False

    def write(self, text, color):
        """Write the given text to the stream in the given color."""
        self.stream.write(colorize(text, color))


class ColorHandler(logging.StreamHandler):

    def __init__(self, stream=sys.stderr):
        super(ColorHandler, self).__init__(_AnsiColorizer(stream))

    def emit(self, record):
        msg_colors = {
            logging.DEBUG: "lgreen",
            logging.INFO: "blue",
            logging.WARNING: "yellow",
            logging.ERROR: "magenta",
            logging.CRITICAL: "red"
        }

        msg = self.format(record)
        color = msg_colors.get(record.levelno, "blue")
        self.stream.write(msg + "\n", color)


class Team:

    def __init__(self, tid, ip, name='', flag_ids=[]):
        self.tid = tid
        self.name = name
        self.ip = ip
        self.flag_ids = flag_ids

        # flags retrieved in the last round
        self.num_flags = 0
        # time spent while performing the last attack on this team
        self.time_elapsed = 10
        # boolean value representing whether a timeout occurred while attacking or not
        self.timed_out = False

    def __repr__(self):
        return f'{self.ip} ({self.name})' if self.name else f'{self.ip}'


class Worker(threading.Thread):
    """Attack one team with the provided exploit and retrieve all the flags."""

    killing_time = threading.Event()

    def __init__(self, n, exploit, service, timeout, do_submit):
        super(Worker, self).__init__()
        # numeric identifier of the worker
        self.n = n
        # file name of the exploit to be executed
        self.exploit = os.path.abspath(exploit)
        # name of the service being attacked
        self.service = service
        # number of seconds to wait before killing an exploit
        self.timeout = timeout
        # team being attacked
        self.team = None
        # list of flags retreived from the attacked team
        self.flags = []
        # make it a daemon thread
        self.daemon = True
        # if true submit flags found
        self.do_submit = do_submit

    def run(self):
        """Extract and execute jobs from the tasks queue until there is
        nothing left to do."""

        # fetch tasks from the queue
        while not Worker.killing_time.is_set():
            try:
                self.team = tasks_noprio.get_nowait()
                self._attack()
            except Empty:
                # terminate if the queue is empty
                break

    def _attack(self):
        """Attack a target: execute the exploit, read its output, extract the
        retrieved flags and submit them."""

        # execute the exploit
        data, time_elapsed, timed_out = self._execute()
        # extract flags from the raw data returned by the script
        self.flags = FLAG_PATTERN.findall(data) if data else []

        flags_to_send = set()
        num_flags = 0
        if self.flags and self.do_submit:
            flags_to_send = set(flag.decode('latin-1') for flag in self.flags)

            # check if the current team is returning too many flags
            num_flags = len(flags_to_send)
            if num_flags > 50:
                logger.warning(self._logalize(f'Returned {num_flags} flags!'))

            # submit the flags
            if flags_to_send:
                submit_flags(flags_to_send)
                logger.debug(
                    self._logalize(
                        'Sent {} flags: {}'.format(
                            num_flags, colorize(', '.join(flags_to_send), 'green')
                )))

        # update stats about the team
        self.team.num_flags = num_flags
        self.team.time_elapsed = time_elapsed
        self.team.timed_out = timed_out

    def _execute(self):
        """Execute the exploit and return the result, kill it if timeouts."""

        # program output
        data = bytes()
        errors = bytes()
        timed_out = False
        elapsed_time = 0
        # record the time elapsed for completion
        time_before = time()
        try:
            logger.debug(self._logalize('Executing'))
            # exploits are always called with 3 or more parameters:
            # ./exploit.sh <team_ip> <team_id> [flag_id ...]
            # if only the ip is needed, the script should ignore the other 2
            # arguments
            proc = subprocess.Popen(
                [self.exploit, self.team.ip, self.team.tid, *self.team.flag_ids],
                preexec_fn=os.setsid, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            data, errors = proc.communicate(timeout=self.timeout)
        except subprocess.TimeoutExpired as e:
            logger.debug(self._logalize(f'Timeout exceeded for pid {proc.pid}'))
            timed_out = True
            # kill the process tree gently and wait a small amount of time for
            # the process to clear resources
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=1)
            # check if the process has terminated and in this case try to
            # kill it with a SIGKILL
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
            data, errors = proc.communicate()
        except OSError as e:
            # the program terminated already
            logger.error(self._logalize(f'Error while executing {self.exploit}: {e}'))
        except Exception as e:
            # wtf happened? this is an unknown error
            logger.error(self._logalize(f'Error: {e}'))
        
        # print the requested output
        if stdout_print:
            print(self._logalize(f'Data: {data}'))
        if stderr_print and len(errors):
            logger.error(self._logalize(f'Error: {errors.decode()}'))

        elapsed_time = time() - time_before

        return data, elapsed_time, timed_out

    def _logalize(self, message):
        """Return a pretty string ready to be logged."""

        return 'team {}: {}'.format(self.team, message)


# functions

def colorize(text, color):
    return '\x1b[{}m{}\x1b[0m'.format(_colors[color], text)


def parse_ips(ips_mixed):
    """Parse a mixed list of IPs and IP ranges and return them as a list."""

    ips = set()
    if isinstance(ips_mixed, str):
        ips_mixed = ips_mixed.split()
    for ip_mixed in ips_mixed:
        ips |= {ip for ip in iptools.IpRange(*ip_mixed.split('-'))}

    return list(ips)


def init_teams(args_ips, service_name):
    """Initialize the global dictionary of teams to attack."""

    global teams

    ips = parse_ips(args_ips) if args_ips else []
    teams = {ip: Team(str(tid), ip) for tid, ip in enumerate(ips)}

    if not teams:
        die('No targets provided')

    # fetch flag_ids and assign them to each team
    flag_ids = get_flagids_service(service_name)
    
    if flag_ids:
        for ip, team in teams.items():
            try:
                team.flag_ids = flag_ids[ip]
            except KeyError:
                logging.warning(f'Unable to find ip {ip} among the flag ids returned by the API')
        logger.debug('Updated the dictionary of targets: {}'.format(teams))


def kill(signal, frame):
    """Instructs the workers to terminate as soon as possible."""

    global death_countdown

    death_countdown -= 1

    if death_countdown <= 0:
        die("It's time to die.")

    logger.critical((
        'Ctrl-C pressed, waiting for workers to timeout and quit... '
        '(press it {} times more to die)').format(
        death_countdown))

    # empty the tasks queue
    try:
        while True:
            tasks_noprio.get_nowait()
    except Empty:
        pass
    # set the killing event
    Worker.killing_time.set()


def die(message):
    logger.critical(message)
    sys.exit(1)    


def watchdog():
    """Called when the tasks queue is not consumed within the round lifespan."""

    logger.warning((
        'Unable to attack the whole range of IPs within the duration '
        'of one round! Increase the number of workers or decrease '
        'the workers timeout'))


def print_team_stats(elapsed_time):
    """Print some stats about the teams attacked in the last round."""

    teams_fast_w_flags = []
    teams_fast_wo_flags = []
    teams_slow_w_flags = []
    teams_slow_wo_flags = []

    for team in teams.values():
        if team.timed_out:
            if team.num_flags:
                teams_slow_w_flags.append(team)
            else:
                teams_slow_wo_flags.append(team)
        else:
            if team.num_flags:
                teams_fast_w_flags.append(team)
            else:
                teams_fast_wo_flags.append(team)

    logger.info((
        '\n'
        'BEGIN of stats for last round\n'
        '=========================================================\n'
        'Time elapsed: {:.3g}s\n'
        'Fast teams with flags: {}\n'
        'Fast teams without flags: {}\n'
        'Timing-out teams with flags: {}\n'
        'Timing-out teams without flags: {}\n'
        '=========================================================\n'
        'END of stats for last round\n').format(
        elapsed_time,
        teams_fast_w_flags, teams_fast_wo_flags,
        teams_slow_w_flags, teams_slow_wo_flags))


def parse_args():
    """Parse command line arguments."""

    parser = argparse.ArgumentParser(description='Exploit execution toolkit')
    group = parser.add_mutually_exclusive_group()

    group.add_argument('-ip', type=str, nargs='+',
                       help='List of IPs or IP ranges to attack')
    parser.add_argument('-x', dest='exploit', type=str, required=True,
                        help='Path of the exploit to be executed (remember to make the exploit executable!)')
    parser.add_argument('-s', dest='service', type=str, required=True,
                        help='Name of the service to attack (it should match the entry found in the flag id endpoint!)')
    parser.add_argument('-1', '--oneshot', dest='oneshot', action='store_true',
                        help='Exit after exploiting the provided teams instead of looping')
    parser.add_argument('-n', dest='num_workers', type=int, default=1,
                        help='Number of concurrent workers (default 1)')
    parser.add_argument('-t', '--timeout', dest='timeout', type=int, default=10,
                        help='Seconds to wait before killing a spawned script (default 10)')
    parser.add_argument('-C', '--no-color', dest='color_log', action='store_false',
                        help='Do not colorize the logs')
    parser.add_argument('-W', '--no-wait', dest='wait_round', action='store_false',
                        help='Continuously attack without waiting for the end of the round, be careful it might cause DoS')
    parser.add_argument('-N', '--no-submit', dest='do_submit', action='store_false',
                        help='Run the attack without submitting captured flags')
    parser.add_argument('-S', '--no-stats', dest='show_stats', action='store_false',
                        help='Disable statistics about the attacked teams')
    parser.add_argument('-p', '--print', dest='stdout_print', action='store_true',
                        help='Print stdout of the exploit')
    parser.add_argument('-e', '--errors', dest='stderr_print', action='store_true',
                        help='Print stderr of the exploit')
    parser.add_argument('-v', dest='verbose', action='count',
                        default=0, help='Set logger level to debug'),

    return parser.parse_args()


def get_flagids_service(service):
    """Get the flag_ids of all teams for a given service."""

    flagids = dict()
    endpoint = FLAGID_URL
    try:
        r = requests.get(endpoint, timeout=BASE_TIMEOUT)
        if r.status_code == 200:
            flagids = r.json()
            if not flagids:
                logger.warning(f'Flag ID JSON empty')    
        elif r.status_code == 404:
            logger.warning(f'Failed fetching {endpoint}: {r.text}')
        else:
            logger.warning(f'Unknown return code {r.status_code} while fetching {endpoint}')
    except requests.exceptions.Timeout as e:
        logger.warning(f'Timeout while fetching {endpoint}')

    try:
        return flagids[service]
    except KeyError:
        logger.warning(f'No flag ids for service {service}')
        return None


def _get_flagids_service(service):
    """Get the flag_ids of all teams for a given service (example from Bambi CTF #7)."""

    flagids = dict()
    endpoint = FLAGID_URL
    try:
        r = requests.get(endpoint, timeout=BASE_TIMEOUT)
        if r.status_code == 200:
            for team_ip, data in r.json()["services"][service].items():
                x = [(int(k),v) for k,v in data.items()]
                p = sorted(x)[-1][1]
                flagids.setdefault(team_ip, []).extend(
                    [item for sl in p.values() for item in sl]
                )
        elif r.status_code == 404:
            logger.warning(f'Failed fetching {endpoint}: {r.text}')
        else:
            logger.warning(f'Unknown return code {r.status_code} while fetching {endpoint}')
    except requests.exceptions.Timeout as e:
        logger.warning(f'Timeout while fetching {endpoint}')


def submit_flags(flags):
    """HTTP-based flag submission."""

    endpoint = FLAG_SUBMISSION_URL
    for flag in flags:
        try:
            r = requests.post(endpoint, data={'team_token': TEAM_TOKEN, 'flag': flag}, timeout=BASE_TIMEOUT)
            if r.status_code == 200:
                if 'Flag accepted' in r.text:
                    logger.info(f'Flag {flag} accepted!')
                else:
                    logger.warning(f'Flag {flag} failed.')
            else:
                logger.warning(f'Invalid HTTP return code {r.status_code} while submitting {flag} to {endpoint}')
        except requests.exceptions.Timeout as e:
            logger.warning(f'Timeout while submitting {flag} to {endpoint}')


def _submit_flags(flags):
    """Socket-based flag submission (example from Bambi CTF #7)."""

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(BASE_TIMEOUT)
        sock.connect((FLAG_SUBMISSION_HOST, FLAG_SUBMISSION_PORT))
        payload = b'\n'.join(s.encode() for s in flags) + b'n'
        sock.sendall(payload)
        sock.close()
    except Exception as e:
        logger.warning(f'Error while sending flags: {e}', exc_info=True)


def main():
    global stdout_print, stderr_print

    args = parse_args()

    # initialize variables
    stdout_print = args.stdout_print
    stderr_print = args.stderr_print
    service_name = args.service  

    # initialize logging
    logging.basicConfig(
        format=LOGGING_FMT,
        level=logging.DEBUG if args.verbose else logging.INFO,
        handlers=[ColorHandler() if args.color_log else logging.StreamHandler()])

    # register the killer handler
    signal.signal(signal.SIGINT, kill)

    while True:
        # get targets to attack
        init_teams(args.ip, service_name)

        # populate the tasks priority queue of tasks
        for team in teams.values():
            tasks_noprio.put_nowait(team)

        # if the loop takes too much time print a warning
        timer = threading.Timer(ROUND_DURATION, watchdog)
        timer.daemon = True
        timer.start()

        # record the elapsed time needed to attack all teams
        time_start = time()

        # create the list of workers and start all of them
        workers = []
        for i in range(args.num_workers):
            workers.append(Worker(i, args.exploit, service_name, args.timeout, args.do_submit))
            workers[i].start()

        # wait responsively: sleep until the queue is empty or an event is thrown
        while not tasks_noprio.empty():
            Worker.killing_time.wait(1)
        # join the workers
        for worker in workers:
            worker.join()
        # reset the timer
        timer.cancel()

        # stop the timer
        elapsed_time = time() - time_start

        # show stats about the attacked teams, if requested
        if args.show_stats:
            print_team_stats(elapsed_time)

        # terminate if it's killing time or if --oneshot is provided
        if Worker.killing_time.is_set() or args.oneshot:
            break

        # wait the end of the round
        seconds_to_round_end = ROUND_DURATION - elapsed_time

        if args.wait_round and seconds_to_round_end > 0:
            logger.info('Sleeping for {} seconds before attacking again'.format(
                seconds_to_round_end))
            sleep(seconds_to_round_end)

    # exit gracefully
    sys.exit(0)


if __name__ == "__main__":
    main()
