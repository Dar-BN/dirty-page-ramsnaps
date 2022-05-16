#!/usr/bin/env python3

import argparse
import json
import logging
import os
import sys

from deepdiff import DeepDiff
from deepdiff.helper import CannotCompare
from pprint import pprint
from itertools import filterfalse


logging.basicConfig()
log = logging.getLogger(os.path.basename(sys.argv[0]))
# log.setLevel(logging.INFO)
log.setLevel(logging.DEBUG)


VOL_KEYS = ['psxview', 'getsids', 'timers', 'callbacks',
            'netscan', 'yarascan', 'handles', 'devicetree',
            'privs', 'pslist', 'ssdt', 'malfind', 'modscan',
            'svcscan', 'dlllist', 'mutantscan', 'ldrmodules']


def has_data_key(obj, key):
    if key in obj:
        return 'data' in obj[key]

    return False


def get_data(obj):

    if obj is None:
        return []

    if 'data' in obj:
        return obj.get('data')

    return obj


def try_load_json(file_path):

    json_data = None

    try:
        with open(file_path, 'r') as fp:
            json_data = json.load(fp)
    except IOError as ex:
        log.debug("Failed to open file %s: %s",
                file_path, str(ex))
        raise ex
    except Exception as ex:
        log.debug("Error loading JSON from %s: %s",
                file_path, str(ex))

    if json_data is None:
        raise ValueError("Invalid data in JSON file %s" % file_path)

    if not isinstance(json_data, dict):
        raise ValueError("Error JSON from %s is not a dictionary" % file_path)

    return json_data


def dict_hash(d):
    return hash(tuple(sorted(
        [(a, tuple(b) if isinstance(b, (list, dict)) else b)
        for a, b in d.items()])))


def compare_json_list(a, b, key_chain=list()):
    assert isinstance(a, list)
    assert isinstance(b, list)

    if len(a) != len(b):
        log.debug("%s - Lengths differ %d != %d",
                ":".join(key_chain), len(a), len(b))

    if len(a) == 0:
        print("A is empty")
        return

    if len(b) == 0:
        print("B is empty")
        return

    if isinstance(a[0], dict):
        for a_index in range(len(a)):
            for b_index in range(len(b)):
                assert isinstance(a[a_index], dict)
                assert isinstance(b[b_index], dict)

                if dict_hash(a[a_index]) != dict_hash(b[b_index]):
                    print("A[%d] != B[%d]" % (a_index, b_index))


def compare_json_dict(a, b, key_chain=list()):
    assert isinstance(a, dict)
    assert isinstance(b, dict)

    log.debug("Key chain: %s", key_chain)
    a_keys = set(a.keys())
    b_keys = set(b.keys())

    print(a_keys)
    return

    only_a = a_keys - b_keys
    only_b = b_keys - a_keys

    if only_a:
        print("Only in a: %s" % str(only_a))

    if only_b:
        print("Only in b: %s" % str(only_b))

    for key in a.keys():
        if key not in b:
            log.debug("Key %s is not in b", key)
            continue

        if not isinstance(a[key], type(b[key])):
            log.error("Types for key %s differs", key)
            continue

        if isinstance(a[key], dict):
            compare_json_dict(a[key], b[key], key_chain + [key])
        elif isinstance(a[key], list):
            compare_json_list(a[key], b[key], key_chain + [key])
        else:
            # Directly compare values
            if a[key] != b[key]:
                print("%s differs: %s != %s" %
                    (",".join(key_chain), a[key], b[key]))

def compare_by_field(field):

    def compare_func(x, y, level=None):
        try:
            return x[field] == y[field]
        except Exception:
            raise CannotCompare() from None

    return compare_func


def compare_by_fields(*fields):

    def compare_func(x, y, _level=None):
        try:
            matched = True
            for field in fields:
                if x[field] != y[field]:
                    matched = False
                    break
            return matched
        except Exception:
            raise CannotCompare() from None

    return compare_func


class VolDiff(object):

    def __init__(self, old_path, new_path,
                 counts=False, new_only=False,
                 show_both=False, force_fields=None):

        self.old = try_load_json(old_path)
        assert isinstance(self.old, dict)

        self.new = try_load_json(new_path)
        assert isinstance(self.new, dict)

        self.new_only = new_only
        self.counts = counts
        self.show_both = show_both
        try:
            self.force_fields = tuple(force_fields) if force_fields else None
        except ValueError as err:
            raise Exception("Invalid value for forced fields: %s" % err)

    @staticmethod
    def filterdiffs(func):

        def _filterdiffs(self, *args, **kwargs):
            try:
                diffs = func(self, *args, **kwargs)
            except CannotCompare:
                log.error("Cannot compare, maybe invalid field?")
                return {}

            new_diffs = None
            if self.new_only:
                new_diffs = {'added': diffs.get('added', [])}
                if self.counts:
                    new_diffs['added_count'] = len(new_diffs['added'])
                return new_diffs

            if not self.show_both:
                new_diffs = {'added': diffs.get('added', []),
                             'deleted': diffs.get('deleted', [])}
                if self.counts:
                    new_diffs['added_count'] = len(new_diffs['added'])
                    new_diffs['deleted_count'] = len(new_diffs['deleted'])
                return new_diffs

            if self.counts:
                diffs['added_counts'] = len(diffs.get('added', []))
                diffs['deleted_counts'] = len(diffs.get('deleted', []))
                diffs['both_counts'] = len(diffs.get('both', []))

            return diffs

        return _filterdiffs

    def compare_list(self, a, b, compare_func):

        added = b[:]
        deleted = list()
        both = list()
        added_seen = list()

        if self.force_fields is not None:
            # Ignore passed compare_func, override with own based on fields
            # given
            compare_func = compare_by_fields(*self.force_fields)

        for _a in a:
            seen = None
            for _b in b:
                if compare_func(_a, _b):
                    seen = _b
                    break

            if seen is None:
                deleted.append(_a)
            else:
                both.append({'old': _a, 'new': _b})
                added_seen.append(seen)

        new_added = added[:]
        for _s in added_seen:
            new_added = filterfalse(lambda x: compare_func(x, _s), new_added)

        return {'added': list(new_added), 'deleted': deleted, 'both': both}

    filtered_compare_list = filterdiffs(compare_list)

    @staticmethod
    def proc_is_hidden(pinfo):

        CONDS = [
            {"pslist": "True",
            "psscan": "True",
            "thrdproc": "False"},
            {"pslist": "False",
            "psscan": "False"}
            ]

        is_hidden = True
        for cond in CONDS:
            is_hidden = True
            for k, v in cond.items():
                if pinfo.get(k, None) is None or pinfo.get(k) != v:
                    is_hidden = False
                    break
            if is_hidden:
                break

        return is_hidden

    def psxview_hidden_procs(self):

        old_hidden = list()
        psxview = self.old.get('psxview', {})
        for proc in get_data(psxview):
            if self.proc_is_hidden(proc):
                old_hidden.append(proc)

        new_hidden = list()
        psxview = self.new.get('psxview', {})
        for proc in get_data(psxview):
            if self.proc_is_hidden(proc):
                new_hidden.append(proc)

        diffs = self.compare_list(old_hidden, new_hidden,
                                  compare_by_field("PID"))
        return diffs

    @filterdiffs
    def compare_connections(self):
        '''
        netscan looks something like:
            {
            "config": {
                "filter": false
            },
            "data": [
                {
                "local_address": "0.0.0.0",
                "local_port": "500",
                "offset": "0x3e6b6570",
                "process_id": "884",
                "protocol": "UDPv4",
                "remote_address": "*",
                "remote_port": "*"
                },
                ...
        '''

        has_data = has_data_key(self.old, "netscan")

        diffs = self.compare_list(get_data(self.old["netscan"])
                                  if "netscan" in self.old else [],
                                  get_data(self.new["netscan"])
                                  if "netscan" in self.new else [],
                                  compare_by_fields(
                                      "process_id",
                                      "local_address",
                                      "local_port",
                                      "remote_address",
                                      "remote_port",
                                  )
                                  if has_data else
                                  compare_by_fields(
                                      "PID",
                                      "LocalAddr",
                                      "ForeignAddr"
                                  ))
        return diffs

    @filterdiffs
    def compare_timers(self):
        '''
        Looks something like:
                ...
        '''

        has_data = has_data_key(self.old, "timers")

        diffs = self.compare_list(get_data(self.old["timers"])
                                  if "timers" in self.old else [],
                                  get_data(self.new["timers"])
                                  if "timers" in self.new else [],
                                  compare_by_field("offset")
                                  if has_data else
                                  compare_by_field("Offset"))
        return diffs

    @filterdiffs
    def compare_handles(self):
        '''
        Looks something like:
            {
            "config": {
                "filter": true
            },
            "data": [
                {
                "handle_granted_access": "131103",
                "handle_name": "MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\HIVELIST",
                "handle_type": "Key",
                "handle_value": "8",
                "process_id": 4
                },

                ...
        '''

        has_data = has_data_key(self.old, "handles")

        diffs = self.compare_list(get_data(self.old["handles"])
                                  if "handles" in self.old else [],
                                  get_data(self.new["handles"])
                                  if "handles" in self.new else [],
                                  compare_by_fields("handle_name",
                                                    "handle_type")
                                  if has_data else
                                  compare_by_fields("Details", "Type"))
        return diffs

    @filterdiffs
    def compare_modules(self):
        '''
        Looks something like:
            {
            "config": {
                "filter": true
            },
            "data": [
                {
                    "kernel_module_base": "0xfffff88003b89000",
                    "kernel_module_file": "\\systemroot\\system32\\drivers\\compositebus.sys",
                    "kernel_module_name": "compositebus.sys",
                    "kernel_module_offset": "0x12b17ca0",
                    "kernel_module_size": 65536
                },
                ...
        '''

        has_data = has_data_key(self.old, "modscan")

        diffs = self.compare_list(get_data(self.old["modscan"])
                                  if "modscan" in self.old else [],
                                  get_data(self.new["modscan"])
                                  if "modscan" in self.new else [],
                                  compare_by_field("kernel_module_file")
                                  if has_data else
                                  compare_by_field("File"))
        return diffs

    @filterdiffs
    def compare_services(self):
        '''
        Looks something like:
            {
            "config": {
                "filter": true
            },
            "data": [
                {
                "process_id": 812,
                "service_binary_path": "C:\\Windows\\System32\\svchost.exe -k LocalSystemNetworkRestricted",
                "service_display_name": "Windows Audio Endpoint Builder",
                "service_name": "AudioEndpointBuilder",
                "service_offset": "0xcf4990",
                "service_order": 28,
                "service_state": "SERVICE_RUNNING",
                "service_type": "SERVICE_WIN32_SHARE_PROCESS"
                },
                {
                ...
        '''

        has_data = has_data_key(self.old, "svcscan")

        diffs = self.compare_list(get_data(self.old["svcscan"])
                                  if "svcscan" in self.old else [],
                                  get_data(self.new["svcscan"])
                                  if "svcscan" in self.new else [],
                                  compare_by_field("service_name")
                                  if has_data else
                                  compare_by_field("ServiceName"))
        return diffs

    @filterdiffs
    def compare_psxview(self):
        '''
        Looks something like:
            {
            "config": {
                "filter": false
            },
            "data": [
                {
                "csrss": "False",
                "deskthrd": "False",
                "process_id": 1792,
                "process_name": "svchost.exe",
                "pslist": "False",
                "pspcid": "False",
                "psscan": "True",
                "session": "False",
                "thrdproc": "False"
                },
                {
                ...
        '''

        has_data = has_data_key(self.old, "psxview")

        diffs = self.compare_list(get_data(self.old["psxview"])
                                  if "psxview" in self.old else [],
                                  get_data(self.new["psxview"])
                                  if "psxview" in self.new else [],
                                  compare_by_field("process_id")
                                  if has_data else
                                  compare_by_field("PID"))
        return diffs

    @filterdiffs
    def compare_malfind(self):
        '''
        Looks something like:
            {
            "config": {
                "filter": true
            },
            "data": [
                {
                "process_id": 488,
                "process_name": "lsass.exe",
                "vad_start": "0x1a0000",
                "vad_tag": "VadS"
                },
                {
                ...
        '''

        has_data = has_data_key(self.old, "malfind")

        diffs = self.compare_list(get_data(self.old["malfind"])
                                  if "malfind" in self.old else [],
                                  get_data(self.new["malfind"])
                                  if "malfind" in self.new else [],
                                  compare_by_field("process_id")
                                  if has_data else
                                  compare_by_field("Pid")
                                  )

        return diffs

    @filterdiffs
    def compare_dlllist(self):
        '''
        Only compares between processes that exist on both.

        Looks something like:
            {
            "config": {
                "filter": true
            },
            "data": [
                {
                "commandline": "",
                "loaded_modules": [],
                "process_id": 4,
                "process_name": "System"
                },
                {
                "commandline": "\\SystemRoot\\System32\\smss.exe",
                "loaded_modules": [
                    {
                    "dll_base": "1204879360",
                    "dll_full_name": "\\SystemRoot\\System32\\smss.exe",
                    "dll_load_count": 65535,
                    "dll_size": "131072"
                    },
                    {
                    "dll_base": "2007629824",
                    "dll_full_name": "C:\\Windows\\SYSTEM32\\ntdll.dll",
                    "dll_load_count": 65535,
                    "dll_size": "1740800"
                    }
                ],
                "process_id": 256,
                "process_name": "smss.exe"
                },
                ...
        '''

        has_data = has_data_key(self.old, "dlllist")

        proc_diffs = self.compare_list(get_data(self.old["dlllist"])
                                       if "dlllist" in self.old else [],
                                       get_data(self.new["dlllist"])
                                       if "dlllist" in self.new else [],
                                       compare_by_field("process_id")
                                       if has_data else
                                       compare_by_fields("Pid", "Path"))

        # Now look at loaded_modules in each process
        module_diffs = []

        if has_data:
            for proc in proc_diffs['both']:
                module_diff = self.filtered_compare_list(
                    proc['old']['loaded_modules'],
                    proc['new']['loaded_modules'],
                    compare_by_field("dll_full_name" if has_data else "Path"))
                if module_diff.get('old', []) or \
                module_diff.get('new', []) or \
                module_diff.get('both', []):
                    new_proc = proc['new']
                    new_proc['loaded_modules'] = module_diff
                    module_diffs.append(new_proc)
        else:
            module_diffs = proc_diffs

        return module_diffs

    @filterdiffs
    def compare_devicetree(self):
        '''
        Looks something like:
            {
            "config": {
                "filter": true
            },
            "data": [
                {
                "devices": [
                    {
                    "device_name": "LanmanServer",
                    "device_offset": "0xfffffa800297e260",
                    "device_type": "FILE_DEVICE_NETWORK",
                    "devices_attached": []
                    }
                ],
                "driver_name": "\\FileSystem\\srv",
                "driver_offset": "0x3e24c060"
                },
                ...
        '''

        has_data = has_data_key(self.old, "devicetree")

        old_devices = []
        new_devices = []
        if has_data:
            if 'devicetree' in self.old:
                old_devices = list(sum([x["devices"]
                                        for x in get_data(self.old['devicetree'])],
                                    []))

            if 'devicetree' in self.new:
                new_devices = list(sum([x["devices"]
                                        for x in get_data(self.new['devicetree'])],
                                    []))
        else:
            old_devices = self.old.get('devicetree', [])
            new_devices = self.new.get('devicetree', [])

        diffs = self.compare_list(old_devices, new_devices,
                                  compare_by_fields("device_name",
                                                    "device_type")
                                  if has_data else
                                  compare_by_fields("Driver Name",
                                                    "Name")
                                  )
        return diffs

    def get_volatility_diffs(self):

        return {
            'devicetree': self.compare_devicetree(),
            'malfind': self.compare_malfind(),
            'psxview': self.compare_psxview(),
            'hidden_processes': self.psxview_hidden_procs(),
            'dlllist':  self.compare_dlllist(),
            'connections':  self.compare_connections(),
            'services': self.compare_services(),
            'modules': self.compare_modules(),
            'handles': self.compare_handles(),
            'timers': self.compare_timers(),
        }


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-d", "--debug", help='Enable debug log',
        action='store_true')

    parser.add_argument(
        "-c", "--count", help='Include counts',
        action='store_true')

    parser.add_argument(
        "-o", "--outdir", help='Write comparisions to directory')

    parser.add_argument(
        "-C", "--compare", help='Compare with CSV list of fields')

    one_only = parser.add_mutually_exclusive_group()

    one_only.add_argument(
        "-n", "--new", help='Show only new elements',
        action='store_true')

    one_only.add_argument(
        "-b", "--both", help='Include elements in both old and new',
        action='store_true')

    parser.add_argument(
        "files", metavar='files', type=str,
        nargs='+', help="Files to compare")

    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    if len(args.files) < 2:
        log.error("Insufficient number of files specified (%s)",
                  len(args.files))
        sys.exit(1)

    if args.outdir and not os.path.exists(args.outdir):
        try:
            log.debug("os.mkdir(%s)", args.outdir)
            os.mkdir(args.outdir)
        except Exception as ex:
            log.error("Failed to create output dir: %s", args.outdir)
            sys.exit(1)

    compare_list = None
    if args.compare:
        try:
            compare_list = args.compare.split(",")
        except Exception as ex:
            log.error("Unable to split compare fields: %s", ex)
            sys.exit(1)

    try:
        for i in range(len(args.files) - 1):
            try:
                log.debug("Comparing %s %s", args.files[i], args.files[i+1])
                diff = VolDiff(args.files[i], args.files[i+1],
                               new_only=args.new,
                               counts=args.count,
                               show_both=args.both,
                               force_fields=compare_list)
            except ValueError as err:
                log.error("Error: %s", err)
                continue

            if args.outdir:
                fname = "diff-%s-vs-%s.json" % (
                    os.path.basename(args.files[i]).removesuffix('.json'),
                    os.path.basename(args.files[i+1]).removesuffix('.json'))
                print("Diffs written to %s" % os.path.join(args.outdir, fname))
                with open(os.path.join(args.outdir, fname), "w") as fp:
                    json.dump(diff.get_volatility_diffs(), fp=fp, indent=2)
            else:
                print("-" * 60)
                print("diff %s %s" % (args.files[i], args.files[i+1]))
                print(json.dumps(diff.get_volatility_diffs(), indent=2))
    except (ValueError, IOError) as ex:
        log.error("Error: %s", ex)
        sys.exit(1)


if __name__ == '__main__':
    main()
