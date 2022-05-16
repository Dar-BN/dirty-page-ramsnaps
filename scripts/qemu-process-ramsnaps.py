#!/usr/bin/env python3

import argparse
import binascii
import logging
import os
import shutil
import sys
from pprint import pformat


logging.basicConfig()
log = logging.getLogger(os.path.basename(sys.argv[0]))
log.setLevel(logging.INFO)



def copy_file(src, dst):
    try:
        log.info("Copying from '%s' to %s'", src, dst)
        shutil.copy(src, dst)

        return True
    except Exception as ex:
        log.error("Failed to copy %s to %s: %s",
                        src, dst, str(ex))
        return False


class Ramsnap(object):
    def __init__(self,
                 files: list = None,
                 output: str = None,
                 prefix: str = None,
                 groups: list = None,
                 search: bool = False):

        if groups and files:
            raise Exception("Only one of groups or files should be provided")

        if not groups and not files:
            raise Exception("Neither one of groups or files was provided")

        if files and not output and not search:
            raise Exception("No output provided when processing files")

        if groups and not prefix:
            raise Exception("No prefix provided when creating groups")

        if groups and type(groups) == list and type(groups[0]) != list:
            raise Exception("Expected a list of lists in groups")

        self._output = output

        self._prefix = prefix

        self._files = files if files is not None else None

        self._groups = groups if groups is not None else None

        # Map from address to file containing most recent entry
        self._addresses = dict()

        # Length of an address field
        self._address_len = 0
        # Distance to next line
        self._next_line_offset = 0

        self._progress = 0

    def _hex2bin(self, hexbytes):
        hexbytes = hexbytes.strip()
        if len(hexbytes) % 2 != 0:
            return binascii.unhexlify(hexbytes[:-1])
        else:
            return binascii.unhexlify(hexbytes)

    def _hex2printable(self, hexbytes, indent=''):

        raw = self._hex2bin(hexbytes)

        try:
            import hexdump
            return f"\n{indent}".join(hexdump.dumpgen(raw))
        except ImportError:
            return raw.decode('utf-8', errors='replace')

    def _write_entry(self, fp, entry):

        address = entry[0:self._address_len]
        data = entry[self._address_len+1:]

        log.debug("Address; %s (%X)", address, int(address, base=16))

        raw = self._hex2bin(data)

        fp.seek(int(address, base=16), os.SEEK_SET)
        fp.write(raw)

    def _print_progress(self, fpath, pos, length):
        if pos == length:
            if sys.stdout.isatty():
                print("\r%s: Progress: 100%% DONE" % fpath)
            else:
                log.info("%s: Progress: 100%% DONE", fpath)
        else:
            new_progress = int((pos * 100) / length)
            if new_progress != self._progress and new_progress < 100:
                self._progress = new_progress
                if sys.stdout.isatty():
                    print("\r%s: Progress: %3d%%" % (fpath, self._progress),
                          end='')
                elif self._progress % 10 == 0:
                    log.info("%s: Progress: %3d%%", fpath, self._progress)
                else:
                    log.debug("%s: Progress: %3d%%", fpath, self._progress)

    def _determine_lengths(self, fpath, chunk):

        if self._address_len == 0:
            # If not done already determine address and line len
            # Should be consistent in all files!
            self._address_len = chunk.find(b':')
            if self._address_len < 0:
                log.error("Unable to determine address len in '%s'",
                          fpath)
                return False

            self._next_line_offset = chunk.find(b'\n')
            if self._next_line_offset < 0:
                log.error("Unable to determine data line len in '%s'".
                          fpath)
                return False

            self._next_line_offset += 1     # include '\n'

    def _update_output(self, outputfp, fpath):
        try:
            with open(fpath, "rb") as fp:
                first_chunk = fp.read(10240)
                # Get file suze
                file_size = fp.seek(0, os.SEEK_END)
                fp.seek(0, os.SEEK_SET)         # Reset to start

                self._determine_lengths(fpath, first_chunk)

                self._write_entry(outputfp,
                                  first_chunk[0:self._next_line_offset-1])

                new_offset = fp.seek(self._next_line_offset, os.SEEK_CUR)
                if new_offset < 0:
                    log.debug('Failed to seek forward; %d', errno)
                    return False

                self._print_progress(fpath, new_offset, file_size)

                while new_offset >= 0:
                    line = fp.read(self._next_line_offset)
                    if line == b"":
                        # EOF
                        break

                    self._write_entry(outputfp, line)

                    new_offset = fp.seek(self._next_line_offset, os.SEEK_CUR)

                    self._print_progress(fpath, new_offset, file_size)
                    if new_offset < 0:
                        log.debug('Failed to seek forward; %d', errno)
                        break

        except Exception as ex:
            log.exception(ex)
            log.error("Failed to open file '%s': %s", fpath, str(ex))

        finally:
            self._print_progress(fpath, file_size, file_size)

        return True

    def _search_entry(self, fpath, hexstr, entry):

        address = entry[0:self._address_len]
        data = entry[self._address_len+1:]

        if hexstr in data:
            print("\nFound in %s at address %s" % (fpath, address))

            i = data.find(hexstr)

            left = max(0, i - 20)
            right = min(len(hexstr) + i + 20, len(data) - len(hexstr))

            print("    %s" % self._hex2printable(data[left:right],
                                                 indent='    '))

    def _search_file(self, fpath, hexstr):
        try:
            with open(fpath, "rb") as fp:
                first_chunk = fp.read(10240)
                # Get file suze
                file_size = fp.seek(0, os.SEEK_END)
                fp.seek(0, os.SEEK_SET)         # Reset to start

                self._determine_lengths(fpath, first_chunk)

                self._search_entry(fpath, hexstr,
                                   first_chunk[0:self._next_line_offset-1])

                new_offset = fp.seek(self._next_line_offset, os.SEEK_CUR)
                if new_offset < 0:
                    log.debug('Failed to seek forward; %d', errno)
                    return False

                self._print_progress(fpath, new_offset, file_size)

                while new_offset >= 0:
                    line = fp.read(self._next_line_offset)
                    if line == b"":
                        # EOF
                        break

                    self._search_entry(fpath, hexstr, line)

                    new_offset = fp.seek(self._next_line_offset, os.SEEK_CUR)

                    self._print_progress(fpath, new_offset, file_size)
                    if new_offset < 0:
                        log.debug('Failed to seek forward; %d', errno)
                        break

        except Exception as ex:
            log.exception(ex)
            log.error("Failed to open file '%s': %s", fpath, str(ex))

        finally:
            self._print_progress(fpath, file_size, file_size)

        return True

    def _create_single_dump(self, path: str, files: list, keep_existing: bool):
        try:
            open_str = "wb"
            if keep_existing:
                # w+b truncates, so use r+b
                open_str = 'r+b'

            with open(path, open_str) as fp:
                fp.seek(0, os.SEEK_SET)         # Reset to start
                if not keep_existing:
                    fp.truncate()

                for f in files:
                    self._update_output(fp, f)

        except Exception as ex:
            log.error("Failed to open output file '%s': %s",
                          path, str(ex))

    def create_dump(self, keep_existing=False):
        self._create_single_dump(self._output, self._files,
                                 keep_existing=keep_existing)

    def generate_group_dumps(self):

        new_files = ["%s-%05d.dmp" % (self._prefix, i)
                     for i in range(len(groups))]
        log.debug("%s", pformat(new_files, indent=2))

        if '/' in self._prefix:
            # It's contains a directory, so create it
            _dir = os.path.dirname(self._prefix)
            if not os.path.exists(_dir):
                try:
                    log.debug("os.mkdir(%s)", _dir)
                    os.mkdir(_dir)
                except Exception as ex:
                    raise Exception("Failed to create output dir: %s" % _dir)

        for i in range(len(groups)):
            if i == 0:
                # First file
                log.debug("self._create_single_dump(%s, %s, %s)",
                          new_files[i],
                          groups[i],
                          False)
                self._create_single_dump(new_files[i],
                                         groups[i],
                                         keep_existing=False)
                continue

            # Subsequent files require copying from previous
            log.debug("copy_file(%s, %s)", new_files[i-1], new_files[i])
            if not copy_file(new_files[i-1], new_files[i]):
                raise Exception("Error creating file %s", new_files[i])

            log.debug("self._create_single_dump(%s, %s, %s)",
                      new_files[i],
                      groups[i],
                      True)
            self._create_single_dump(new_files[i],
                                     groups[i],
                                     keep_existing=True)


    def search(self, string):

        # hexstr = "".join("{0:02x}".format(c) for c in string.encode())
        # hexstr = hexstr.encode()
        hexstr = binascii.hexlify(string.encode())

        for f in self._files:
            self._search_file(f, hexstr)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-o", "--output", help="File to write to")
    group.add_argument(
        "-s", "--search", help="Search for a string")
    group.add_argument(
        "-p", "--prefix", help="Prefix for combined files from index")

    parser.add_argument(
        "-i", "--index", help="Read image files from given index")

    parser.add_argument(
        "-g", "--grouping", help="Combine in groups of N", type=int,
        default=1)

    parser.add_argument(
        "-m", "--maxdumps", help="Maximum number of dumps", type=int)

    parser.add_argument(
        "-a", "--append", help="Existing image to append to")

    parser.add_argument(
        "-d", "--debug", help='Enable debug log',
        action='store_true')

    parser.add_argument('files', metavar='file', type=str,
                        nargs='*', help="Files to process")

    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    if args.output:
        if not args.files:
            log.error("No files specified")
            sys.exit(1)

        ramsnap = Ramsnap(files=args.files, output=args.output)

        keep_existing = False
        if args.append:
            # copy to new output
            if not copy_file(args.append, args.output):
                log.error("Failed to copy %s to %s: %s",
                              args.append, args.output, str(ex))
                sys.exit(1)

            keep_existing = True

        ramsnap.create_dump(keep_existing=keep_existing)
    elif args.prefix:
        if not args.index:
            log.error("No index file specified")
            sys.exit(1)

        if not os.path.exists(args.index):
            log.error("Index file doesn't exist: %s", args.index)
            sys.exit(1)

        log.info("Reading index file %s", args.index)
        with open(args.index, "r") as fp:
            entries = fp.readlines()
        log.info("Found %d entries", len(entries))

        files = list()
        for entry in entries:
            entry = entry.strip()

            if not entry:
                continue

            if not os.path.exists(entry):
                log.warning("Entry %s doesn't exist, skipping...", entry)
                continue

            stat = os.stat(entry)
            if stat.st_size == 0:
                log.warning("Entry %s is empty, skipping...", entry)
                continue

            files.append(entry)

        log.info("Found %d existing files", len(files))

        if len(files) < 1:
            log.error("Nothing to do, no valid snaphots found")
            sys.exit(1)

        grouping = args.grouping
        num_snaps = len(files)
        max_snaps = max(1, (num_snaps - 2) // 2)

        log.debug("Num snaps = %d", num_snaps)
        log.debug("Max snaps = %d", max_snaps)

        if args.maxdumps:
            # Takes priority over groupings if specified
            if args.maxdumps < 4:
                log.error("Max dumps has a minumum value of 4")
                sys.exit(1)

            if num_snaps < args.maxdumps:
                log.info("Num snaps (%d) less than max dumps (%d), will do no grouping",
                         num_snaps, args.maxdumps)
                grouping = 1

            elif args.maxdumps > (num_snaps - 2) / 2:
                log.info("Num snaps (%d) cannot combine in groups larger than 2 for max %d dumps",
                         num_snaps, args.maxdumps)
                grouping = 2

            else:
                # Calculate based on 1 start and 1 final dump
                grouping = num_snaps // (args.maxdumps - 2)
                if grouping > max_snaps:
                    grouping = max_snaps

                log.info("Max dumps of %d requires groups of %d",
                         args.maxdumps, grouping)

        if grouping:
            if grouping < 1 or grouping > max_snaps:
                log.error("Group number should be in range 1 to %d",
                              max_snaps)
                sys.exit(1)

            log.info("Will combine in groups of %d", grouping)

            groups = list()
            groups.append([files[0]])

            for i in range(1, num_snaps, grouping):
                if i + grouping > num_snaps:
                    end = len(files)
                else:
                    end = i + grouping
                groups.append(files[i:end])

            log.debug("%s", pformat(groups, indent=2))
            log.info("Will result in %d dumps", len(groups))

        ramsnap = Ramsnap(prefix=args.prefix, groups=groups)

        ramsnap.generate_group_dumps()
    else:
        ramsnap = Ramsnap(files=args.files, search=True)

        ramsnap.search(args.search)
