#!/usr/bin/env python3
#
#  Migration Stream Analyzer
#
#  Copyright (c) 2015 Alexander Graf <agraf@suse.de>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see <http://www.gnu.org/licenses/>.

import abc
import argparse
import binascii
import collections
import enum
import json
import logging
import os
import select
import socket
import stat
import struct
import sys
import time


logging.basicConfig()
log = logging.getLogger(os.path.basename(sys.argv[0]))
log.setLevel(logging.INFO)


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError:
        pass


class MigrationWriterInterface(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def write64(self, value):
        raise NotImplementedError

    @abc.abstractmethod
    def write32(self, value):
        raise NotImplementedError

    @abc.abstractmethod
    def write16(self, value):
        raise NotImplementedError

    @abc.abstractmethod
    def write8(self, value):
        raise NotImplementedError

    @abc.abstractmethod
    def writestr(self, value, len=None):
        raise NotImplementedError

    @abc.abstractmethod
    def writevar(self, value, size=None):
        raise NotImplementedError


class MigrationSocketWriter(MigrationWriterInterface):

    def __init__(self, reader):
        self._socket = reader.get_socket()

    def write64(self, value):
        return self._socket.send(value.to_bytes(8, 'big'))

    def write32(self, value):
        return self._socket.send(value.to_bytes(4, 'big'))

    def write16(self, value):
        return self._socket.send(value.to_bytes(2, 'big'))

    def write8(self, value):
        return self._socket.send(value.to_bytes(1, 'big'))

    def writestr(self, value, len=None):
        return self.writevar(value.encode('utf-8'), len)

    def writevar(self, value, size=None):
        if size is None:
            size = len(value)
        if size == 0:
            return
        written = self.write8(size)
        if written != 1:
            raise Exception("Failed to write 1 byte")

        written = self._socket.send(value)
        if written != size:
            raise Exception("Failed to write %d bytes, wrote" %
                            (size, written))


class MigrationReaderInterface(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def is_file(self):
        raise NotImplementedError

    @abc.abstractmethod
    def get_file(self):
        raise NotImplementedError

    @abc.abstractmethod
    def undo(self):
        raise NotImplementedError

    @abc.abstractmethod
    def skip_bytes(self, number):
        raise NotImplementedError

    @abc.abstractmethod
    def read64(self):
        raise NotImplementedError

    @abc.abstractmethod
    def read32(self):
        raise NotImplementedError

    @abc.abstractmethod
    def read16(self):
        raise NotImplementedError

    @abc.abstractmethod
    def read8(self):
        raise NotImplementedError

    @abc.abstractmethod
    def readstr(self, len=None):
        raise NotImplementedError

    @abc.abstractmethod
    def readvar(self, size=None):
        raise NotImplementedError


class MigrationSocketReader(MigrationReaderInterface):
    def __init__(self, sock):
        self._socket = sock
        self._last_read = bytearray()
        self._undo_buffer = bytearray()

    def get_socket(self):
        return self._socket

    def is_file(self):
        return False

    def get_file(self):
        return None

    def undo(self):
        # self._dump_as_hex(self._last_read, 'undo')
        self._undo_buffer.extend(self._last_read)

    def skip_bytes(self, num):
        log.debug("skipping %d bytes", num)
        num_read = 0
        to_read = num

        while num_read < num:
            read_bytes = self._recv(to_read)
            num_read += len(read_bytes)
            to_read = num - num_read

    def _dump_as_hex(self, data, prefix="data"):
        if not data:
            print("\n%s: <empty>" % prefix)

        for i in range(len(data)):
            if i % 16 == 0:
                print("\n%s(%06d of %06d): " % (prefix, i, len(data)), end="")
            print("%02x " % data[i], end="")

        print("")

    def _recv(self, num_bytes):
        to_read = num_bytes
        to_return = bytearray()

        if self._undo_buffer:
            if len(self._undo_buffer) <= num_bytes:
                to_read -= len(self._undo_buffer)
                to_return = self._undo_buffer
                self._undo_buffer = bytearray()
            elif len(self._undo_buffer) > num_bytes:
                to_return = self._undo_buffer[:num_bytes]
                self._undo_buffer = self._undo_buffer[num_bytes:]
            else:
                raise Exception("Failed to handle %d bytes (%d)" %
                                (num_bytes, len(self._last_read)))

        while to_read > 0:
            read_bytes = self._socket.recv(to_read)
            to_return.extend(read_bytes)
            to_read -= len(read_bytes)
            if len(read_bytes) == 0:
                raise Exception(
                    "Failed to read enough bytes (connection broken?)")

        self._last_read = to_return[:]

        # self._dump_as_hex(to_return)
        return to_return

    def read64(self):
        return int.from_bytes(self._recv(8), byteorder='big',
                              signed=True)

    def read32(self):
        return int.from_bytes(self._recv(4), byteorder='big',
                              signed=True)

    def read16(self):
        return int.from_bytes(self._recv(2), byteorder='big',
                              signed=True)

    def read8(self):
        return int.from_bytes(self._recv(1), byteorder='big',
                              signed=True)

    def readstr(self, len=None):
        try:
            return self.readvar(len).decode('utf-8')
        except Exception as ex:
            # import pdb; pdb.set_trace()
            raise ex

    def readvar(self, size=None):
        if size is None:
            size = self.read8()
        if size == 0:
            return b""
        value = self._recv(size)
        if len(value) != size:
            raise Exception("Unexpected end of socket")

        return value


class MigrationFileReader(MigrationReaderInterface):
    def __init__(self, filename):
        self.filename = filename
        self._file = open(self.filename, "rb")
        self._last_read_size = 0

    def is_file(self):
        return True

    def get_file(self):
        return self._file

    def undo(self):
        if self._last_read_size:
            self._file.seek(-self._last_read_size, 1)

    def skip_bytes(self, number):
        self._file.seek(number, 1)

    def read64(self):
        self._last_read_size = 8
        return int.from_bytes(self._file.read(8), byteorder='big', signed=True)

    def read32(self):
        self._last_read_size = 4
        return int.from_bytes(self._file.read(4), byteorder='big', signed=True)

    def read16(self):
        self._last_read_size = 2
        return int.from_bytes(self._file.read(2), byteorder='big', signed=True)

    def read8(self):
        self._last_read_size = 1
        return int.from_bytes(self._file.read(1), byteorder='big', signed=True)

    def readstr(self, len=None):
        return self.readvar(len).decode('utf-8')

    def readvar(self, size=None):
        self._read_size = 0
        if size is None:
            self._read_size += 1
            size = self.read8()
        if size == 0:
            return b""
        value = self._file.read(size)
        self._read_size += size
        if len(value) != size:
            raise Exception("Unexpected end of %s at 0x%x" %
                            (self.filename, self._file.tell()))
        return value

    def tell(self):
        return self._file.tell()

    # The VMSD description is at the end of the file, after EOF. Look for
    # the last NULL byte, then for the beginning brace of JSON.
    def read_migration_debug_json(self):
        QEMU_VM_VMDESCRIPTION = 0x06

        # Remember the offset in the file when we started
        entrypos = self._file.tell()

        # Read the last 10MB
        self._file.seek(0, os.SEEK_END)
        endpos = self._file.tell()
        self._file.seek(max(-endpos, -10 * 1024 * 1024), os.SEEK_END)
        datapos = self._file.tell()
        data = self._file.read()
        # The full file read closed the file as well, reopen it
        self._file = open(self.filename, "rb")

        # Find the last NULL byte, then the first brace after that. This should
        # be the beginning of our JSON data.
        nulpos = data.rfind(b'\0')
        jsonpos = data.find(b'{', nulpos)

        # Check backwards from there and see whether we guessed right
        self._file.seek(datapos + jsonpos - 5, 0)
        if self.read8() != QEMU_VM_VMDESCRIPTION:
            raise Exception("No Debug Migration device found")

        jsonlen = self.read32()

        # Seek back to where we were at the beginning
        self._file.seek(entrypos, 0)

        # explicit decode() needed for Python 3.5 compatibility
        return data[jsonpos:jsonpos + jsonlen].decode("utf-8")

    def close(self):
        self._file.close()


class RamSection(object):
    RAM_SAVE_FLAG_ZERO = 0x02
    RAM_SAVE_FLAG_MEM_SIZE = 0x04
    RAM_SAVE_FLAG_PAGE = 0x08
    RAM_SAVE_FLAG_EOS = 0x10
    RAM_SAVE_FLAG_CONTINUE = 0x20
    RAM_SAVE_FLAG_XBZRLE = 0x40
    RAM_SAVE_FLAG_HOOK = 0x80
    RAM_SAVE_FLAG_COMPRESS_PAGE = 0x100

    def __init__(self, reader, version_id, ramargs, section_key):
        if version_id != 4:
            raise Exception("Unknown RAM version %d" % version_id)

        self.reader = reader
        self.section_key = section_key
        self.TARGET_PAGE_SIZE = ramargs['page_size']
        self.dump_memory = ramargs['dump_memory']
        self.write_memory = ramargs['write_memory']
        self.pcram_prefix = ramargs['pcram_prefix']
        self.pcram_prefix_idx = "%s.idx" % self.pcram_prefix
        self.sizeinfo = collections.OrderedDict()
        self.data = collections.OrderedDict()
        self.data['section sizes'] = self.sizeinfo
        self._name = ''
        self.files = {}
        if self.dump_memory:
            self.memory = collections.OrderedDict()
            self.data['memory'] = self.memory

    def __repr__(self):
        return self.data.__repr__()

    def __str__(self):
        return self.data.__str__()

    def getDict(self):
        return self.data

    def _print_flags(self, flag):
        flag_str = ""
        flag_str += "ZERO," \
            if flag & self.RAM_SAVE_FLAG_ZERO else ""
        flag_str += "MEM_SIZE," \
            if flag & self.RAM_SAVE_FLAG_MEM_SIZE else ""
        flag_str += "PAGE," \
            if flag & self.RAM_SAVE_FLAG_PAGE else ""
        flag_str += "EOS," \
            if flag & self.RAM_SAVE_FLAG_EOS else ""
        flag_str += "CONTINUE," \
            if flag & self.RAM_SAVE_FLAG_CONTINUE else ""
        flag_str += "XBZRLE," \
            if flag & self.RAM_SAVE_FLAG_XBZRLE else ""
        flag_str += "HOOK," \
            if flag & self.RAM_SAVE_FLAG_HOOK else ""
        flag_str += "COMPRESS_PAGE," \
            if flag & self.RAM_SAVE_FLAG_COMPRESS_PAGE else ""
        log.debug("Flags = %s", flag_str)

    def index_append_file(self, fname):
        with open(self.pcram_prefix_idx, "a+") as fp:
            fp.write(fname)
            fp.write("\n")

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        if value == "pc.ram":
            if self.pcram_prefix is not None:
                self._pcram_prefix_str = "%s-%d" % (
                    self.pcram_prefix, time.time_ns())
                log.error("pcram prefix: %s",
                              self._pcram_prefix_str)
                # Open file to match
                f = open(self._pcram_prefix_str, "wb")
                f.truncate(0)
                self.files[self._pcram_prefix_str] = f
                self.index_append_file(self._pcram_prefix_str)
        else:
            if self._pcram_prefix_str in self.files:
                self.files[self._pcram_prefix_str].close()
                del self.files[self._pcram_prefix_str]

            self._pcram_prefix_str = None

        self._name = value

    def read(self):

        # Read all RAM sections
        while True:
            addr = self.reader.read64()
            log.debug('addr = 0x%016x', addr)
            flags = addr & (self.TARGET_PAGE_SIZE - 1)
            log.debug('flags = 0x%016x', flags)
            addr &= ~(self.TARGET_PAGE_SIZE - 1)
            log.debug('new_addr = 0x%016x', addr)

            # self._print_flags(flags)
            if flags & self.RAM_SAVE_FLAG_MEM_SIZE:
                while True:
                    namelen = self.reader.read8()
                    # We assume that no RAM chunk is big enough to ever
                    # hit the first byte of the address, so when we see
                    # a zero here we know it has to be an address, not the
                    # length of the next block.
                    if namelen == 0:
                        self.reader.undo()
                        break
                    self.name = self.reader.readstr(len=namelen)
                    log.error("memsize: %s", self.name)
                    len = self.reader.read64()
                    self.sizeinfo[self.name] = '0x%016x' % len
                    if len == 0:
                        print("Got 0 len!")
                        self.reader.undo()
                        break
                    if self.write_memory:
                        print(self.name)
                        mkdir_p('./' + os.path.dirname(self.name))
                        f = open('./' + self.name, "wb")
                        f.truncate(0)
                        f.truncate(len)
                        self.files[self.name] = f
                flags &= ~self.RAM_SAVE_FLAG_MEM_SIZE

            if flags & self.RAM_SAVE_FLAG_COMPRESS_PAGE:
                if flags & self.RAM_SAVE_FLAG_CONTINUE:
                    flags &= ~self.RAM_SAVE_FLAG_CONTINUE
                else:
                    self.name = self.reader.readstr()
                    log.error("compress-page: %s", self.name)
                fill_char = self.reader.read8()
                # The page in question is filled with fill_char now
                if self.write_memory and fill_char != 0:
                    self.files[self.name].seek(addr, os.SEEK_SET)
                    self.files[self.name].write(
                        chr(fill_char) * self.TARGET_PAGE_SIZE)
                if self.dump_memory:
                    self.memory['%s (0x%016x)' % (self.name, addr)
                                ] = 'Filled with 0x%02x' % fill_char
                flags &= ~self.RAM_SAVE_FLAG_COMPRESS_PAGE
            elif flags & self.RAM_SAVE_FLAG_PAGE:
                if flags & self.RAM_SAVE_FLAG_CONTINUE:
                    flags &= ~self.RAM_SAVE_FLAG_CONTINUE
                else:
                    self.name = self.reader.readstr()
                    log.error("page: %s", self.name)

                if self.write_memory or self.dump_memory or self.pcram_prefix:
                    data = self.reader.readvar(size=self.TARGET_PAGE_SIZE)
                else:
                    self.reader.skip_bytes(self.TARGET_PAGE_SIZE)

                if self._pcram_prefix_str is not None:
                    # hexdata = "".join("{0:02x}".format(c) for c in data)
                    hexdata = binascii.hexlify(data)
                    self.files[self._pcram_prefix_str].write(
                        b"0x%016x: %s\n" % (addr, hexdata))

                if self.write_memory:
                    self.files[self.name].seek(addr, os.SEEK_SET)
                    self.files[self.name].write(data)
                if self.dump_memory:
                    hexdata = " ".join("{0:02x}".format(c) for c in data)
                    self.memory['%s (0x%016x)' % (self.name, addr)] = hexdata

                flags &= ~self.RAM_SAVE_FLAG_PAGE
            elif flags & self.RAM_SAVE_FLAG_ZERO:
                if flags & self.RAM_SAVE_FLAG_CONTINUE:
                    flags &= ~self.RAM_SAVE_FLAG_CONTINUE
                else:
                    self.name = self.reader.readstr()
                    log.error("zero: %s", self.name)
                fill_char = self.reader.read8()
                # The page in question is filled with fill_char now
                if self.write_memory and fill_char != 0:
                    self.files[self.name].seek(addr, os.SEEK_SET)
                    self.files[self.name].write(
                        chr(fill_char) * self.TARGET_PAGE_SIZE)
                if self.dump_memory:
                    self.memory['%s (0x%016x)' % (self.name, addr)
                                ] = 'Filled with 0x%02x' % fill_char

                if self._pcram_prefix_str is not None:
                    hexdata = b"%02x" % (fill_char)
                    hexdata = hexdata * self.TARGET_PAGE_SIZE
                    self.files[self._pcram_prefix_str].write(
                        b"0x%016x: %s\n" % (addr, hexdata))

                flags &= ~self.RAM_SAVE_FLAG_ZERO
            elif flags & self.RAM_SAVE_FLAG_XBZRLE:
                raise Exception("XBZRLE RAM compression is not supported yet")
            elif flags & self.RAM_SAVE_FLAG_HOOK:
                raise Exception("RAM hooks don't make sense with files")

            # End of RAM section
            if flags & self.RAM_SAVE_FLAG_EOS:
                break

            if flags != 0:
                raise Exception("Unknown RAM flags: %x" % flags)

    def __del__(self):
        if self.write_memory:
            for key in self.files:
                self.files[key].close()


class HTABSection(object):
    HASH_PTE_SIZE_64 = 16

    def __init__(self, file, version_id, device, section_key):
        if version_id != 1:
            raise Exception("Unknown HTAB version %d" % version_id)

        self.file = file
        self.section_key = section_key

    def read(self):

        header = self.file.read32()

        if (header == -1):
            # "no HPT" encoding
            return

        if (header > 0):
            # First section, just the hash shift
            return

        # Read until end marker
        while True:
            index = self.file.read32()
            n_valid = self.file.read16()
            n_invalid = self.file.read16()

            if index == 0 and n_valid == 0 and n_invalid == 0:
                break

            self.file.readvar(n_valid * self.HASH_PTE_SIZE_64)

    def getDict(self):
        return ""


class ConfigurationSection(object):
    def __init__(self, file):
        self.file = file

    def read(self):
        name_len = self.file.read32()
        name = self.file.readstr(len=name_len)


class MigCmd(enum.Enum):
    # Possible Commands
    MIG_CMD_INVALID = 0
    MIG_CMD_OPEN_RETURN_PATH = 1
    MIG_CMD_PING = 2
    MIG_CMD_POSTCOPY_ADVISE = 3
    MIG_CMD_POSTCOPY_LISTEN = 4
    MIG_CMD_POSTCOPY_RUN = 5
    MIG_CMD_POSTCOPY_RAM_DISCARD = 6
    MIG_CMD_POSTCOPY_RESUME = 7
    MIG_CMD_PACKAGED = 8
    MIG_CMD_RECV_BITMAP = 9
    MIG_CMD_MAX = 10


class MigRpMsg(enum.Enum):
    # Responses to Commands
    MIG_RP_MSG_INVALID = 0        # must be 0
    MIG_RP_MSG_SHUT = 1           # sibling will not send any more rp messages
    MIG_RP_MSG_PONG = 2           # response to a ping; data (seq: be32 )
    MIG_RP_MSG_REQ_PAGES_ID = 3   # data (start: be64, len: be32, id: string)
    MIG_RP_MSG_REQ_PAGES = 4      # data (start: be64, len: be32)
    MIG_RP_MSG_RECV_BITMAP = 5    # send recved_bitmap back to source
    MIG_RP_MSG_RESUME_ACK = 6     # tell source that we are ready to resume
    MIG_RP_MSG_MAX = 7


class CommandSection(object):
    # Possible Commands
    MIG_CMD_INFO = [
        (-1, "INVALID"),
        (0, "OPEN_RETURN_PATH"),
        (4, "PING"),
        (-1, "POSTCOPY_ADVISE"),
        (0, "POSTCOPY_LISTEN"),
        (0, "POSTCOPY_RUN"),
        (-1, "POSTCOPY_RAM_DISCARD"),
        (-1, "PoSTCOPY_RESUME"),
        (-1, "PACKAGED"),
        (-1, "RECV_BITMAP"),
        (0, "MAX")
    ]

    def __init__(self, reader):
        self._reader = reader
        self._writer = None

    def handle_command(self):
        cmd = self._reader.read16()
        cmd_len = self._reader.read16()

        if cmd >= MigCmd.MIG_CMD_MAX.value:
            raise Exception("Invalid command; %x" % cmd)

        if self.MIG_CMD_INFO[cmd][0] != -1 and \
                cmd_len != self.MIG_CMD_INFO[cmd][0]:
            raise Exception("Invalid command; %x" % cmd)

        print("Got Command: %s (%s)" % (self.MIG_CMD_INFO[cmd][1], cmd))

        if cmd == MigCmd.MIG_CMD_OPEN_RETURN_PATH.value:
            self.handle_cmd_open_return_path()
        elif cmd == MigCmd.MIG_CMD_PING.value:
            self.handle_cmd_ping()
        elif cmd == MigCmd.MIG_CMD_POSTCOPY_ADVISE.value:
            self.handle_cmd_postcopy_advise()
        elif cmd == MigCmd.MIG_CMD_POSTCOPY_LISTEN.value:
            self.handle_cmd_postcopy_listen()
        elif cmd == MigCmd.MIG_CMD_POSTCOPY_RUN.value:
            self.handle_cmd_postcopy_run()
        elif cmd == MigCmd.MIG_CMD_POSTCOPY_RAM_DISCARD.value:
            self.handle_cmd_postcopy_ram_discard()
        elif cmd == MigCmd.MIG_CMD_POSTCOPY_RESUME.value:
            self.handle_cmd_postcopy_resume()
        elif cmd == MigCmd.MIG_CMD_PACKAGED.value:
            self.handle_cmd_packaged()
        elif cmd == MigCmd.MIG_CMD_RECV_BITMAP.value:
            self.handle_cmd_recv_bitmap()

    def handle_cmd_open_return_path(self):
        print("Opening Return Path")
        self._writer = MigrationSocketWriter(self._reader)

    def handle_cmd_ping(self):
        print("Sending PONG")
        sess_id = self._reader.read32()
        self._writer.write16(MigRpMsg.MIG_RP_MSG_PONG.value)
        self._writer.write16(4)  # Size of 32-bit number
        self._writer.write32(sess_id)

    def handle_cmd_postcopy_advise(self):
        pass

    def handle_cmd_postcopy_listen(self):
        pass

    def handle_cmd_postcopy_run(self):
        pass

    def handle_cmd_postcopy_ram_discard(self):
        pass

    def handle_cmd_postcopy_resume(self):
        pass

    def handle_cmd_packaged(self):
        pass

    def handle_cmd_recv_bitmap(self):
        pass


class VMSDFieldGeneric(object):
    def __init__(self, desc, file):
        self.file = file
        self.desc = desc
        self.data = ""

    def __repr__(self):
        return str(self.__str__())

    def __str__(self):
        return " ".join("{0:02x}".format(c) for c in self.data)

    def getDict(self):
        return self.__str__()

    def read(self):
        size = int(self.desc['size'])
        self.data = self.file.readvar(size)
        return self.data


class VMSDFieldInt(VMSDFieldGeneric):
    def __init__(self, desc, file):
        super(VMSDFieldInt, self).__init__(desc, file)
        self.size = int(desc['size'])
        self.format = '0x%%0%dx' % (self.size * 2)
        self.sdtype = '>i%d' % self.size
        self.udtype = '>u%d' % self.size

    def __repr__(self):
        if self.data < 0:
            return ('%s (%d)' % ((self.format % self.udata), self.data))
        else:
            return self.format % self.data

    def __str__(self):
        return self.__repr__()

    def getDict(self):
        return self.__str__()

    def read(self):
        super(VMSDFieldInt, self).read()
        self.sdata = int.from_bytes(self.data, byteorder='big', signed=True)
        self.udata = int.from_bytes(self.data, byteorder='big', signed=False)
        self.data = self.sdata
        return self.data


class VMSDFieldUInt(VMSDFieldInt):
    def __init__(self, desc, file):
        super(VMSDFieldUInt, self).__init__(desc, file)

    def read(self):
        super(VMSDFieldUInt, self).read()
        self.data = self.udata
        return self.data


class VMSDFieldIntLE(VMSDFieldInt):
    def __init__(self, desc, file):
        super(VMSDFieldIntLE, self).__init__(desc, file)
        self.dtype = '<i%d' % self.size


class VMSDFieldBool(VMSDFieldGeneric):
    def __init__(self, desc, file):
        super(VMSDFieldBool, self).__init__(desc, file)

    def __repr__(self):
        return self.data.__repr__()

    def __str__(self):
        return self.data.__str__()

    def getDict(self):
        return self.data

    def read(self):
        super(VMSDFieldBool, self).read()
        if self.data[0] == 0:
            self.data = False
        else:
            self.data = True
        return self.data


class VMSDFieldStruct(VMSDFieldGeneric):
    QEMU_VM_SUBSECTION = 0x05

    def __init__(self, desc, file):
        super(VMSDFieldStruct, self).__init__(desc, file)
        self.data = collections.OrderedDict()

        # When we see compressed array elements, unfold them here
        new_fields = []
        for field in self.desc['struct']['fields']:
            if not 'array_len' in field:
                new_fields.append(field)
                continue
            array_len = field.pop('array_len')
            field['index'] = 0
            new_fields.append(field)
            for i in range(1, array_len):
                c = field.copy()
                c['index'] = i
                new_fields.append(c)

        self.desc['struct']['fields'] = new_fields

    def __repr__(self):
        return self.data.__repr__()

    def __str__(self):
        return self.data.__str__()

    def read(self):
        for field in self.desc['struct']['fields']:
            try:
                reader = vmsd_field_readers[field['type']]
            except:
                reader = VMSDFieldGeneric

            field['data'] = reader(field, self.file)
            field['data'].read()

            if 'index' in field:
                if field['name'] not in self.data:
                    self.data[field['name']] = []
                a = self.data[field['name']]
                if len(a) != int(field['index']):
                    raise Exception(
                        "internal index of data field unmatched (%d/%d)" %
                        (len(a), int(field['index'])))
                a.append(field['data'])
            else:
                self.data[field['name']] = field['data']

        if 'subsections' in self.desc['struct']:
            for subsection in self.desc['struct']['subsections']:
                if self.file.read8() != self.QEMU_VM_SUBSECTION:
                    raise Exception("Subsection %s not found at offset %x" % (
                        subsection['vmsd_name'], self.file.tell()))
                name = self.file.readstr()
                version_id = self.file.read32()
                self.data[name] = VMSDSection(
                    self.file, version_id, subsection, (name, 0))
                self.data[name].read()

    def getDictItem(self, value):
        # Strings would fall into the array category, treat
        # them specially
        if value.__class__ is ''.__class__:
            return value

        try:
            return self.getDictOrderedDict(value)
        except:
            try:
                return self.getDictArray(value)
            except:
                try:
                    return value.getDict()
                except:
                    return value

    def getDictArray(self, array):
        r = []
        for value in array:
            r.append(self.getDictItem(value))
        return r

    def getDictOrderedDict(self, dict):
        r = collections.OrderedDict()
        for (key, value) in dict.items():
            r[key] = self.getDictItem(value)
        return r

    def getDict(self):
        return self.getDictOrderedDict(self.data)


vmsd_field_readers = {
    "bool": VMSDFieldBool,
    "int8": VMSDFieldInt,
    "int16": VMSDFieldInt,
    "int32": VMSDFieldInt,
    "int32 equal": VMSDFieldInt,
    "int32 le": VMSDFieldIntLE,
    "int64": VMSDFieldInt,
    "uint8": VMSDFieldUInt,
    "uint16": VMSDFieldUInt,
    "uint32": VMSDFieldUInt,
    "uint32 equal": VMSDFieldUInt,
    "uint64": VMSDFieldUInt,
    "int64 equal": VMSDFieldInt,
    "uint8 equal": VMSDFieldInt,
    "uint16 equal": VMSDFieldInt,
    "float64": VMSDFieldGeneric,
    "timer": VMSDFieldGeneric,
    "buffer": VMSDFieldGeneric,
    "unused_buffer": VMSDFieldGeneric,
    "bitmap": VMSDFieldGeneric,
    "struct": VMSDFieldStruct,
    "unknown": VMSDFieldGeneric,
}


class VMSDSection(VMSDFieldStruct):
    def __init__(self, file, version_id, device, section_key):
        self.file = file
        self.data = ""
        self.vmsd_name = ""
        self.section_key = section_key
        desc = device
        if 'vmsd_name' in device:
            self.vmsd_name = device['vmsd_name']

        # A section really is nothing but a FieldStruct :)
        super(VMSDSection, self).__init__({'struct': desc}, file)

###############################################################################


class MigrationDump(object):
    QEMU_VM_FILE_MAGIC = 0x5145564d
    QEMU_VM_FILE_VERSION = 0x00000003
    QEMU_VM_EOF = 0x00
    QEMU_VM_SECTION_START = 0x01
    QEMU_VM_SECTION_PART = 0x02
    QEMU_VM_SECTION_END = 0x03
    QEMU_VM_SECTION_FULL = 0x04
    QEMU_VM_SUBSECTION = 0x05
    QEMU_VM_VMDESCRIPTION = 0x06
    QEMU_VM_CONFIGURATION = 0x07
    QEMU_VM_RP_COMMAND = 0x08
    QEMU_VM_SECTION_FOOTER = 0x7e

    def __init__(self, filename=None, sock=None):
        self.section_classes = {('ram', 0): [RamSection, None],
                                ('spapr/htab', 0): (HTABSection, None)}

        self.vmsd_desc = None
        self.reader = None

        self.filename = filename
        if filename is not None:
            self.reader = MigrationFileReader(filename)

        self.socket = sock
        if sock is not None:
            self.reader = MigrationSocketReader(sock)

        if self.reader is None:
            raise Exception("Failed to determine reader")

        self._command_handler = None

        self._section_id = None

    def read_header(self):
        # Read in the header

        # File magic
        data = self.reader.read32()
        if data != self.QEMU_VM_FILE_MAGIC:
            if self.filename is not None:
                raise Exception("Invalid magic %x (offset: %d)" %
                                (data, self.reader.tell()))
            else:
                raise Exception("Invalid magic %x" % data)

        # Version (has to be v3)
        data = self.reader.read32()
        if data != self.QEMU_VM_FILE_VERSION:
            if self.filename is not None:
                raise Exception("Invalid version number %d (offset: %d)" %
                                (data, self.reader.tell()))
            else:
                raise Exception("Invalid version number %d" % data)

    def read_section(self):
        section_type = self.reader.read8()

        if section_type == self.QEMU_VM_EOF:
            return False
        elif section_type == self.QEMU_VM_RP_COMMAND:
            if self._command_handler is None:
                self._command_handler = CommandSection(self.reader)
            self._command_handler.handle_command()
        elif section_type == self.QEMU_VM_CONFIGURATION:
            section = ConfigurationSection(self.reader)
            section.read()
        elif section_type == self.QEMU_VM_SECTION_START or \
                section_type == self.QEMU_VM_SECTION_FULL:

            self._section_id = self.reader.read32()
            name = self.reader.readstr()
            log.info("Reading section: %s", name)
            instance_id = self.reader.read32()
            version_id = self.reader.read32()
            section_key = (name, instance_id)
            classdesc = self.section_classes[section_key]
            section = classdesc[0](
                self.reader, version_id, classdesc[1], section_key)
            self.sections[self._section_id] = section
            section.read()
        elif section_type == self.QEMU_VM_SECTION_PART or \
                section_type == self.QEMU_VM_SECTION_END:
            self._section_id = self.reader.read32()
            self.sections[self._section_id].read()
        elif section_type == self.QEMU_VM_SECTION_FOOTER:
            read_section_id = self.reader.read32()
            if read_section_id != self._section_id:
                raise Exception("Mismatched section footer: %x vs %x" % (
                    read_section_id, section_id))
        else:
            raise Exception("Unknown section type: %d" % section_type)

        return True

    def read(self, desc_only=False, dump_memory=False, write_memory=False,
             header=True, pcram_prefix=None):

        if header:
            self.read_header()

        if self.filename:
            # Read in the whole file
            self.load_vmsd_json(self.reader)

        # Read sections
        self.sections = collections.OrderedDict()

        if desc_only:
            return

        ramargs = {}
        ramargs['page_size'] = self.vmsd_desc['page_size'] \
            if self.vmsd_desc else 4096
        ramargs['dump_memory'] = dump_memory
        ramargs['write_memory'] = write_memory
        ramargs['pcram_prefix'] = pcram_prefix
        self.section_classes[('ram', 0)][1] = ramargs

        while True:
            if not self.read_section():
                break

        self.reader.close()

    def load_vmsd_json(self, file):
        vmsd_json = file.read_migration_debug_json()
        self.vmsd_desc = json.loads(
            vmsd_json, object_pairs_hook=collections.OrderedDict)
        for device in self.vmsd_desc['devices']:
            key = (device['name'], device['instance_id'])
            value = (VMSDSection, device)
            self.section_classes[key] = value

    def getDict(self):
        r = collections.OrderedDict()
        for (key, value) in self.sections.items():
            key = "%s (%d)" % (value.section_key[0], key)
            r[key] = value.getDict()
        return r


class MigrationSocketHandler(object):
    def __init__(self, socket_path, save_pcram=None, outdir=None):
        if os.path.exists(socket_path):
            raise Exception("'%s' already exists!" % socket_path)

        self._socket_path = socket_path

        self._outdir = outdir

        self._client_socket = None

        self._server_socket = socket.socket(socket.AF_UNIX,
                                            socket.SOCK_NONBLOCK +
                                            socket.SOCK_STREAM)
        self._server_socket.bind(self._socket_path)
        self._server_socket.listen(1)

        self._header_read = False
        self._dump_parser = None

        self._save_pcram = save_pcram

    def wait_for_client(self):
        while self.wait_for_input(True):
            try:
                (client_sock, _dummy) = self._server_socket.accept()
                self._client_socket = client_sock
                self._dump_parser = MigrationDump(sock=self._client_socket)
                return True
            except BlockingIOError:
                pass

        return False

    def handle_client_connection(self):

        if self.wait_for_input():
            if not self._header_read:
                self._dump_parser.read_header()

        pcram_prefix = None
        while True:
            if self._save_pcram:
                pcram_prefix = os.path.join(self._outdir, "pc-ram")
            self._dump_parser.read(header=False,
                                   pcram_prefix=pcram_prefix)
            time.sleep(200)

    def wait_for_input(self, server=False, timeout=60.0) -> bool:
        remaining_timeout = timeout
        while True:
            # Do this everytime, may become None if client has disconnected
            r_socks = []
            if server and self._server_socket is not None:
                r_socks.append(self._server_socket)
            elif self._client_socket is not None:
                r_socks.append(self._client_socket)
            else:
                return False

            (r_fds, w_fds, ex_fds) = select.select(r_socks, [], [], 5.0)
            if not r_fds:
                remaining_timeout -= 5.0
                print("remaining_timeout: %2.1f" % remaining_timeout)
                if remaining_timeout < 0:
                    return False

                # timeout
                continue

            if r_socks[0] in r_fds:
                return True
            else:
                return False

    def client_close(self):
        if self._client_socket is not None:
            self._client_socket.close()
            self._client_socket = None

    def close_all(self):
        self.client_close()

        if self._server_socket is not None:
            self._server_socket.close()
            self._server_socket = None

        if self._socket_path is not None and \
                os.path.exists(self._socket_path):
            os.unlink(self._socket_path)

###############################################################################


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, VMSDFieldGeneric):
            return str(o)
        return json.JSONEncoder.default(self, o)


def handle_file_args(args):
    jsonenc = JSONEncoder(indent=4, separators=(',', ': '))

    if args.extract:
        dump = MigrationDump(args.file)

        dump.read(desc_only=True)
        print("desc.json")
        f = open("desc.json", "w")
        f.truncate()
        f.write(jsonenc.encode(dump.vmsd_desc))
        f.close()

        dump.read(header=False, write_memory=True)
        dict = dump.getDict()
        print("state.json")
        f = open("state.json", "w")
        f.truncate()
        f.write(jsonenc.encode(dict))
        f.close()
    elif args.dump == "state":
        dump = MigrationDump(args.file)
        dump.read(dump_memory=args.memory)
        dict = dump.getDict()
        print(jsonenc.encode(dict))
    elif args.dump == "desc":
        dump = MigrationDump(args.file)
        dump.read(desc_only=True)
        print(jsonenc.encode(dump.vmsd_desc))
    else:
        raise Exception("Please specify either -x, -d state or -d desc")


def handle_socket_args(args):

    if not os.path.exists(args.outdir) or not os.path.isdir(args.outdir):
        print("Output directory doesn't exist, or is not a directory: %s" %
              args.outdir)
        sys.exit(1)

    sock = None

    try:
        sock = MigrationSocketHandler(args.socket, save_pcram=True,
                                    outdir=args.outdir)
        while sock.wait_for_client():
            log.info("A client connected")
            sock.handle_client_connection()

    except Exception as ex:
        print("Error: %s" % ex)
    finally:
        if sock is not None:
            sock.close_all()

        if os.path.exists(args.socket):
            os.unlink(args.socket)


if __name__ == '__main__':
    rc = 0
    try:
        parser = argparse.ArgumentParser()

        parser.add_argument(
            "-D", "--debug", help='Enable debug logging', action='store_true')

        sockgroup = parser.add_argument_group('sockets')
        sockgroup.add_argument(
            "-s", "--socket", help='migration dump socket to read from')
        sockgroup.add_argument(
            "-o", "--outdir",
            help='directory to write migration dumps to (default = $PWD)',
            default=os.getcwd())

        filegroup = parser.add_argument_group('files')
        filegroup.add_argument(
            "-f", "--file", help='migration dump to read from')
        filegroup.add_argument(
            "-m", "--memory", help='dump RAM contents as well',
            action='store_true')
        filegroup.add_argument(
            "-d", "--dump", help='what to dump ("state" or "desc")',
            default='state')
        filegroup.add_argument(
            "-x", "--extract", help='extract contents into individual files',
            action='store_true')

        args = parser.parse_args()

        if args.debug:
            log.getLogger().setLevel(log.DEBUG)

        if args.socket is None and args.file is None:
            print("Please specify file or socket to read from")
            sys.exit(1)

        if args.socket:
            try:
                handle_socket_args(args)
            except Exception as ex:
                log.exception(ex)
                raise ex

        elif args.file:
            try:
                handle_file_args(args)
            except Exception as ex:
                log.exception(ex)
                raise ex
    except Exception as ex:
        print("Exception: %s" % ex, file=sys.stderr)
        rc = 1
    finally:
        print("Exiting with status: %d" % rc, file=sys.stderr)
        sys.exit(rc)
