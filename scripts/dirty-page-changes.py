#!/usr/bin/env python3

import logging
import argparse
import sys
import os

logging.basicConfig()
log = logging.getLogger(os.path.basename(sys.argv[0]))
log.setLevel(logging.INFO)


HEADING_LINE = 'address,num_changes'


def process_file(fpath, page_info):

    log.debug("Processing file: %s", fpath)

    if not os.path.exists(fpath):
        log.error("File %s doesn't exist", fpath)
        return

    stat = os.stat(fpath)
    if stat.st_size == 0:
        log.error("File %s is empty", fpath)
        return

    try:
        with open(fpath, "r") as fp:
            line = fp.readline()
            while line:
                address = line.split(":")[0]
                if address in page_info:
                    page_info[address] += 1
                else:
                    page_info[address] = 1

                line = fp.readline()
    except Exception as ex:
        log.error("Error processing %s: %s", fpath, ex)
        return


parser = argparse.ArgumentParser()

parser.add_argument("-d", "--debug", action="store_true",
                    help="Enable debug messages")

parser.add_argument("-o", "--output",
                    help="Output file",
                    required=True)

parser.add_argument("files", nargs="+", help="Files to process")

args = parser.parse_args()

if args.debug:
    log.setLevel(logging.DEBUG)

if os.path.exists(args.output):
    log.error("Error: The output file %s already exists!", args.output)
    sys.exit(1)

page_changes = dict()

for fpath in args.files:
    process_file(fpath, page_changes)

if not page_changes:
    log.error("Failed to parse any data!")
    sys.exit(1)

with open(args.output, "w") as fp:
    fp.write(HEADING_LINE)
    fp.write("\n")
    sorted_keys = list(page_changes.keys())
    sorted_keys.sort()
    for address in sorted_keys:
        fp.write("%s,%d\n" % (address, page_changes[address]))

sys.exit(0)
