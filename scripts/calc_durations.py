#!/usr/bin/env python3

import argparse
import sys
import os
import logging
import re


logging.basicConfig()
log = logging.getLogger(os.path.basename(sys.argv[0]))
log.setLevel(logging.INFO)

# Match nano-seconds
ns_re = re.compile(r'.*-(\d{16,19})\D*')
# Match micro-seconds
ms_re = re.compile(r'.*-(\d{10,13})\D*')

parser = argparse.ArgumentParser()

units = parser.add_mutually_exclusive_group()

units.add_argument("-3", "--milli", action="store_true",
                   default=True, help="Milli-seconds")

units.add_argument("-6", "--micro", action="store_true",
                   help="Micro-seconds")

units.add_argument("-9", "--nano", action="store_true",
                   help="Nano-seconds")

parser.add_argument("-d", "--debug", action="store_true",
                    help="Enable debug messages")

parser.add_argument("files", help="Files to process", nargs='+')

args = parser.parse_args()

if args.debug:
    log.setLevel(logging.DEBUG)

# List of nanosecond timestamps (10^-9)
tstamps = list()
for file in args.files:
    ns_m = ns_re.match(file)
    ms_m = ms_re.match(file)
    matched = None
    if ns_m:
        matched = ns_m.groups()[0]
        try:
            tstamps.append(int(matched))
        except ValueError as err:
            log.error("Couldn't convert %s to int: %s",
                      matched, err)
    elif ms_m:
        matched = ms_m.groups()[0]
        try:
            tstamps.append(int(matched) * 10**6)
        except ValueError as err:
            log.error("Couldn't convert %s to int: %s",
                      matched, err)
    else:
        log.debug("Skipping %s, no match",
                  file)

log.debug("Got tstamps: %s", tstamps)


if args.micro:
    divisor = 10**3
    unit_str = "microseconds"
    spacing = 12
elif args.nano:
    divisor = 1
    unit_str = "nanoseconds"
    spacing = 16
else:
    divisor = 10**6
    unit_str = "milliseconds"
    spacing = 8

prev = 0
tstamps.sort()
print("%*s" % (spacing, unit_str))
for ts in tstamps:
    if prev == 0:
        prev = ts
        continue
    diff = ts - prev
    print("%*d" % (spacing, diff / divisor))
    prev = ts
