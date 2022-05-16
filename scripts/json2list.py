#!/usr/bin/env python3

import argparse
import json
import logging
import os
import sys
import string

logging.basicConfig()
log = logging.getLogger(os.path.basename(sys.argv[0]))
# log.setLevel(logging.INFO)
log.setLevel(logging.DEBUG)


HEX_COLS = ("address", "offset(p)", "offset(v)", "callback", "base")
SERVICES_HEX_COLS = HEX_COLS + ("start", )
ALLOWED_CHARS = set(string.printable) - set(string.whitespace)


def filter_string(s):
    return filter(lambda x: x in ALLOWED_CHARS, s)


def filter_values(values):
    return [x if not isinstance(x. str) else filter_string(x) for x in values]


def list_table(table, title, wide=False, diff=None, delim=None, mono=None):

    print()
    print("=" * 70)
    print("%s%s" % (title,
                    f" ({diff})" if diff else ""))
    print("=" * 70)

    if not table:
        print("No entries in table")
        return

    if not isinstance(table, list):
        log.error("Invalid table")
        return

    if not isinstance(table[0], dict):
        log.error("Invalid table row 0")
        return

    if diff == 'both':
        keys = table[0]['old'].keys()
    else:
        keys = table[0].keys()

    if diff:
        indent = "  "
    else:
        indent = ""

    if not delim:
        delim = ""

    if mono:
        verb = "="
    else:
        verb = ""

    header_fmt = ""
    if wide:
        line_fmt = f"{delim} " if delim else ""
        header = ""
        header_fmt = f"{delim}"
        for k in keys:
            if k.lower() in \
                    (SERVICES_HEX_COLS if title == "services" else HEX_COLS):
                max_len = 20   # Fixed format
            else:
                if diff == 'both':
                    max_len = max(
                        [len(str(row['old'][k])) for row in table])
                else:
                    max_len = max(
                        [len(str(row[k])) for row in table])
            max_len += len(f"{verb}{verb}{delim}")
            if k.lower() in \
                    (SERVICES_HEX_COLS if title == "services" else HEX_COLS):
                line_fmt += f"{verb}0x%016x{verb}     {delim} "
            else:
                line_fmt += "{2}%-{0}.{0}s{2} {1} ".format(
                    max_len, delim, verb)
            header_fmt += "%-{0}.{0}s {1} ".format(max_len, delim)
            header += "-" * max_len
            header += "  "
    else:
        line_fmt = f"{delim} " if delim else ""
        for k in keys:
            if k.lower() in \
                    (SERVICES_HEX_COLS if title == "services" else HEX_COLS):
                line_fmt += f"{verb}0x%016x{verb}    {delim} "
            else:
                line_fmt += f"{verb}%-20.20s{verb} {delim} "
            header_fmt += f"%-20.20s {delim} "
        header = "--------------------  " * len(keys)

    row_num = 0
    try:
        line = header_fmt % tuple(keys)
        print(indent + line)
        print(indent + header)
    except Exception as ex:
        log.error("Error on title row: %s", ex)
        return

    for row in table:
        line = ""
        try:
            if diff is None:
                line = line_fmt % tuple(row.values())
            elif diff == 'added':
                if row_num == 0:
                    line += "0a0,{0}\n".format(len(table))
                line += "> " + line_fmt % tuple(row.values())
            elif diff == 'both':
                old_line = line_fmt % tuple(row['old'].values())
                new_line = line_fmt % tuple(row['new'].values())

                if old_line != new_line:
                    # Only if not the same
                    line += '{0}c{0}\n'.format(row_num+1)
                    line += "< " + old_line
                    line += "\n---\n"
                    line += "> " + new_line
            elif diff == 'deleted':
                if row_num == 0:
                    line += "0,{0}d0\n".format(len(table))
                line += "< " + line_fmt % tuple(row.values())

            if line:
                print(line)
        except Exception as ex:
            log.error("Error on row %d: %s", row_num, ex)
        finally:
            row_num += 1


parser = argparse.ArgumentParser()

parser.add_argument("-f", "--file",
                    help="File to process",
                    required=True)

parser.add_argument("-w", "--wide",
                    help="Full strings in output",
                    action="store_true")

parser.add_argument("-m", "--mono",
                    help="Add org-mode monospace to fields",
                    action="store_true")

parser.add_argument("-D", "--delim",
                    help="Deliminator between columns")

parser.add_argument("tables",
                    help="Tables to list ( use 'help' for a list)",
                    nargs="+")

args = parser.parse_args()


if not os.path.exists(args.file):
    log.error("File %s doesn't exist", args.file)
    sys.exit(1)

content = {}
try:
    with open(args.file, 'r') as fp:
        content = json.load(fp)
except Exception as ex:
    log.error("Error opening file %s: %s", args.file, ex)
    sys.exit(1)

if not content:
    log.error("File %s doesn't contain valid content",
              args.file)
    sys.exit(1)

table_list = args.tables

if "help" in table_list:
    print("Available tables:\n")
    print(("  %s\n" * len(content.keys())) %
          (tuple(content.keys())))
    sys.exit(0)

if "all" in table_list:
    table_list = list(content.keys())

print("Processing file: %s\n" % args.file)
for table_name in table_list:
    if table_name in content and "added" in content[table_name]:
        for state in 'added', 'both', 'deleted':
            if state in content[table_name]:
                list_table(content[table_name][state],
                           "Table: %s" % table_name,
                           wide=args.wide,
                           diff=state,
                           delim=args.delim,
                           mono=args.mono)

    elif table_name in content:
        list_table(content.get(table_name, []),
                   "Table: %s" % table_name,
                   wide=args.wide,
                   delim=args.delim,
                   mono=args.mono)
    else:
        log.error("Table %s doesn't exist, skipping...",
                  table_name)
        continue

    print("\n")

sys.exit(0)
