#!/usr/bin/env python3
import threading
import time
import sys
import os
import logging
import json
import argparse

from queue import Queue, SimpleQueue, Empty
from subprocess import Popen, PIPE

logging.basicConfig()
log = logging.getLogger(os.path.basename(sys.argv[0]))
# log.setLevel(logging.INFO)
log.setLevel(logging.DEBUG)

queue = Queue()
resultq = SimpleQueue()

start = time.time()

plugins = ["callbacks", "devicetree", "dlllist", "getsids", "handles",
           "ldrmodules", "malfind", "modscan", "mutantscan", "netscan",
           "privs", "pslist", "psxview", "ssdt", "svcscan", "timers",
           "yarascan"]


def map_cols_func(_cols):

    def _map_cols(_row):

        res = {}

        for k, v in zip(_cols, _row):
            #print(k, v)
            res[k] = v

        return res

    return _map_cols


def remap_cols(obj):
    new_obj = {}
    for k in obj.keys():
        #print(cont[k]['columns'])
        #print(cont[k]['rows'])
        new_obj[k] = list(
            map(map_cols_func(obj[k].get('columns')),
                obj[k].get('rows')))

    return new_obj

class ThreadVol(threading.Thread):
    """Threaded Volatility"""

    def __init__(self, que, profile, vol_path):
        threading.Thread.__init__(self)
        self.queue = que
        self.profile = profile
        self.vol_path = vol_path

    def run(self):
        while True:
            plugin, memfile = self.queue.get()
            try:
                # grabs plugin from queue

                #  Run volatility
                cmd = [self.vol_path, "--output=json", "-l",
                       "file://" + memfile,
                       "--profile=" + self.profile, plugin]
                log.info(" ".join(cmd))
                proc = Popen(cmd, stdout=PIPE, stderr=PIPE)
                stdout, stderr = proc.communicate()
                if stderr:
                    log.error("%s: %s", plugin, stderr.decode())

                try:
                    s = stdout.decode()
                    if s and s[0] != '{':
                        # Looks like mixed output, find JSON...
                        i = s.find('{')
                        if i == -1:
                            raise ValueError("Failed to find JSON (%s)" %
                                             plugin)
                        s = s[i:]
                    elif not s:
                        raise ValueError("Received no input (%s)" % plugin)

                    j = json.loads(s)
                    resultq.put({plugin: j})
                except ValueError as err:
                    print("Parse Error: ", err, ": ", stdout.decode())

                # signals to queue job is done
            except Exception as ex:
                log.error("Exception processing %s using %s: %s",
                          memfile, plugin, ex)
            finally:
                self.queue.task_done()


#  Get profile of a memfile
def get_profile(file, vol_path):
    cmd = vol_path+" -f "+file+" imageinfo"
    print(cmd)
    proc = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
    stdout, stderr = proc.communicate()
    print(stderr)
    for line in stdout.split('\n'):
        if "Suggested Profile(s)" in line:
            profile = line.split(": ")
            if len(profile) > 1:
                profile = profile[1].split(",")[0].split("(")[0]
                return profile
    return ""


def main(argv):
    global plugins, plugins_all
    hlp = "autoVol.py -f MEMFILE -o OUTFILE " \
          "[-e VOLATILITY-PATH] [-a] [-p PROFILE] "\
          "[-c 'plugin1,plugin2,plugin3']"

    parser = argparse.ArgumentParser()

    parser.add_argument("-p", "--profile", help="profile to use")

    parser.add_argument("-P", "--plugins", help="plugins to run")

    parser.add_argument("-v", "--volatility-path",
                        help="path to vol.py",
                        required=True)

    parser.add_argument("-t", "--threads", help="number of threads",
                        type=int)

    parser.add_argument("files", help="memory dumps to process",
                        nargs='+')

    args = parser.parse_args()

    if args.volatility_path:
        if not os.path.exists(args.volatility_path):
            log.error("Path to volatility %s doesn't exist",
                      args.volatility_path)
            sys.exit(1)

    #  Get profile of the memfile
    profile = args.profile
    if not args.profile:
        profile = get_profile(args.file, args.volatility_path)
        if profile == "":
            print("Not profile found! you can set "
                  "the profile using the -p option")
            sys.exit()

    threads = int(args.threads)

    log.info("Using profile: %s", profile)
    log.info("Using %s threads", threads)

    # run X threads
    for i in range(threads):
        t = ThreadVol(queue, profile,
                      args.volatility_path)
        t.daemon = True
        t.start()
        time.sleep(0.1)

    for file in args.files:
        try:
            log.info("Processing file: %s", file)

            if not os.path.exists(file):
                log.error("File in path %s does not exists", file)
                continue

            outfile = "%s.json" % file

            # populate queue with data
            if not args.plugins:   # If not, use default plugins
                for plugin in plugins:
                    queue.put((plugin, file))

            else:   # If plugins provided
                plugins = args.plugins.split(",")
                for plugin in plugins:
                    queue.put((plugin, file))

        except Exception as ex:
            log.error("Error executing volatility for %s: %s", file, ex)
        finally:
            # wait on the queue until everything has been processed
            queue.join()

        log.info("Elapsed Time: %s", time.time() - start)

        try:
            result = {}
            while not resultq.empty():
                try:
                    res = resultq.get_nowait()
                    new_res = remap_cols(res)
                    result.update(new_res)
                except Empty:
                    pass

            if result:
                with open(outfile, "w") as fp:
                    json.dump(result, fp=fp, indent=2)
                log.info("Output written to %s", outfile)
            else:
                log.warning("No results generated for %s", file)

        except Exception as ex:
            log.error("Error processing %s: %s", file, ex)


if __name__ == "__main__":
    main(sys.argv[1:])
