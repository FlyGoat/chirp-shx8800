# Copyright 2020 Jiauxn Yang <jiaxun.yang@flygoat.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""SenHaiX 8800 radio management module"""

import struct
import time
import os
import logging

from chirp import util, chirp_common, bitwise, errors, directory, memmap
from chirp.settings import RadioSetting, RadioSettingGroup, \
                RadioSettingValueBoolean, RadioSettingValueList, \
                RadioSettingValueInteger, RadioSettingValueString, \
                RadioSettingValueFloat, RadioSettings

LOG = logging.getLogger(__name__)

MEM_SIZE = 0x1c00
CMD_ACK = "\x06"
BLOCK_SIZE = 64

def _rawrecv(radio, amount):
    """Raw read from the radio device"""
    data = ""
    try:
        data = radio.pipe.read(amount)
    except:
        msg = "Generic error reading data from radio; check your cable."
        raise errors.RadioError(msg)

    if len(data) != amount:
        msg = "Error reading data from radio: not the amount of data we want."
        raise errors.RadioError(msg)

    return data


def _rawsend(radio, data):
    """Raw send to the radio device"""
    try:
        radio.pipe.write(data)
    except:
        raise errors.RadioError("Error sending data to radio")


def _make_frame(cmd, addr, length, data=""):
    """Pack the info in the headder format"""
    frame = struct.pack(">BHB", ord(cmd), addr, length)
    # add the data if set
    if len(data) != 0:
        frame += data

    return frame

def SHX8800_prep(radio):
    """Prepare radio device for transmission"""
    _rawsend(radio, "PROGROM")
    _rawsend(radio, "SHX")
    _rawsend(radio, "U")
    ack = _rawrecv(radio, 1)
    if ack != CMD_ACK:
        raise errors.RadioError("Radio did not ACK first command")

    _rawsend(radio, "F")
    ident = _rawrecv(radio, 8)
    if len(ident) != 8:
        LOG.debug(util.hexprint(ident))
        raise errors.RadioError("Radio did not send identification")

    LOG.info("Ident: " + util.hexprint(ident))

def SHX8800_exit(radio):
    """Exit programming mode"""
    _rawsend(radio, "E")

def _recv_block(radio, addr, blocksize):
    """Receive a block from the radio ROM"""
    _rawsend(radio, _make_frame("R", addr, blocksize))

    # read 4 bytes of header
    hdr = _rawrecv(radio, 4)

    # read data
    data = _rawrecv(radio, blocksize)

    # DEBUG
    LOG.debug("Response:")
    LOG.debug("\n " + util.hexprint(data))

    c, a, l = struct.unpack(">BHB", hdr)
    if a != addr or l != blocksize or c != ord("R"):
        LOG.error("Invalid answer for block 0x%04x:" % addr)
        LOG.error("CMD: %s  ADDR: %04x  SIZE: %02x" % (c, a, l))
        raise errors.RadioError("Unknown response from the radio")

    return data

def _write_block(radio, addr, blocksize, data):
    """Write a block to the radio ROM"""
    # Send CMD + Data
    _rawsend(radio, _make_frame("W", addr, blocksize, data))

    # read response
    resp = _rawrecv(radio, 1)

    if resp != CMD_ACK:
        raise errors.RadioError("No ACK from the radio")


def do_download(radio):
    """ The download function """
    SHX8800_prep(radio)

    # UI progress
    status = chirp_common.Status()
    status.cur = 0
    status.max = MEM_SIZE
    status.msg = "Cloning from radio..."
    radio.status_fn(status)
    data = ""

    for addr in range(0x0000, MEM_SIZE, BLOCK_SIZE):
        data += _recv_block(radio, addr, BLOCK_SIZE)
        # UI Update
        status.cur = addr
        radio.status_fn(status)

    SHX8800_exit(radio)

    return memmap.MemoryMap(data)


def do_upload(radio):
    """The upload function"""
    SHX8800_prep(radio)

    # UI progress
    status = chirp_common.Status()
    status.cur = 0
    status.max = MEM_SIZE
    status.msg = "Cloning to radio..."
    radio.status_fn(status)

    for addr in range(0x0000, MEM_SIZE, BLOCK_SIZE):
        _write_block(radio, addr, BLOCK_SIZE, 
                    radio._mmap[addr:addr+BLOCK_SIZE])
        # UI Update
        status.cur = addr
        radio.status_fn(status)

    SHX8800_exit(radio)


SHX8800_MEM_FORMAT = """
struct {
  lbcd rxfreq[4];
  lbcd txfreq[4];
  ul16 rxtone;
  ul16 txtone;
  u8 scode;
  u8 pttid;
  u8 power_lvl;
  u8 spare1:1,
     narrow:1,
     spare0:2,
     busy_lock:1,
     scan:1,
     allow_emission:1,
     encryption:1;
} memory[128];

#seekto 0xc00;
struct {
  char name[16];
} names[128];

"""

SHX8800_POWER_LEVELS = [chirp_common.PowerLevel("High", watts=5.00),
                     chirp_common.PowerLevel("Low",  watts=1.00)]

SHX8800_DTCS = sorted(chirp_common.DTCS_CODES + [645])

PTTID_LIST = ["Off", "BOT", "EOT", "Both"]
PTTIDCODE_LIST = ["%s" % x for x in range(1, 16)]
STEPS = [2.5, 5.0, 6.25, 10.0, 12.5, 25.0]


@directory.register
class SenHaiX8800Radio(chirp_common.CloneModeRadio):
    """SenHaiX 8800"""
    VENDOR = "SenHaiX"
    MODEL = "8800"
    BAUD_RATE = 9600

    def get_features(self):
        rf = chirp_common.RadioFeatures()
        rf.has_settings = True
        rf.has_bank = False
        rf.has_cross = True
        rf.has_rx_dtcs = True
        rf.has_tuning_step = False
        rf.can_odd_split = True
        rf.valid_name_length = 7
        rf.valid_characters = chirp_common.CHARSET_ASCII
        rf.valid_skips = ["", "S"]
        rf.valid_tmodes = ["", "Tone", "TSQL", "DTCS", "Cross"]
        rf.valid_cross_modes = ["Tone->Tone", "Tone->DTCS", "DTCS->Tone",
                                "->Tone", "->DTCS", "DTCS->", "DTCS->DTCS"]
        rf.valid_power_levels = SHX8800_POWER_LEVELS
        rf.valid_duplexes = ["", "-", "+", "split", "off"]
        rf.valid_modes = ["FM", "NFM"]
        rf.valid_tuning_steps = STEPS

        rf.valid_bands = [(118000000, 176000000), (400000000, 521000000)]
        rf.memory_bounds = (0, 127)

        return rf

    def sync_in(self):
        self._mmap = do_download(self)
        self.process_mmap()

    def sync_out(self):
        do_upload(self)

    def process_mmap(self):
        self._memobj = bitwise.parse(SHX8800_MEM_FORMAT, self._mmap)

    def _is_txinh(self, _mem):
        raw_tx = ""
        for i in range(0, 4):
            raw_tx += _mem.txfreq[i].get_raw()
        return raw_tx == "\xFF\xFF\xFF\xFF"

    def _get_mem(self, number):
        return self._memobj.memory[number]

    def _get_nam(self, number):
        return self._memobj.names[number]

    def get_memory(self, number):
        _mem = self._get_mem(number)
        _nam = self._get_nam(number)

        mem = chirp_common.Memory()
        mem.number = number

        if _mem.get_raw()[0] == "\xff":
            mem.empty = True
            return mem

        mem.freq = int(_mem.rxfreq) * 10

        if self._is_txinh(_mem):
            mem.duplex = "off"
            mem.offset = 0
        elif int(_mem.rxfreq) == int(_mem.txfreq):
            mem.duplex = ""
            mem.offset = 0
        elif abs(int(_mem.rxfreq) * 10 - int(_mem.txfreq) * 10) > 70000000:
            mem.duplex = "split"
            mem.offset = int(_mem.txfreq) * 10
        else:
            mem.duplex = int(_mem.rxfreq) > int(_mem.txfreq) and "-" or "+"
            mem.offset = abs(int(_mem.rxfreq) - int(_mem.txfreq)) * 10

        for char in _nam.name:
            if str(char) == "\xFF":
                char = " "
            mem.name += str(char)
        mem.name = mem.name.rstrip()

        dtcs_pol = ["N", "N"]

        if _mem.txtone in [0, 0xFFFF]:
            txmode = ""
        elif _mem.txtone >= 0x0258:
            txmode = "Tone"
            mem.rtone = int(_mem.txtone) / 10.0
        elif _mem.txtone <= 0x0258:
            txmode = "DTCS"
            if _mem.txtone > 0x69:
                index = _mem.txtone - 0x6A
                dtcs_pol[0] = "R"
            else:
                index = _mem.txtone - 1
            mem.dtcs = SHX8800_DTCS[index]
        else:
            LOG.warn("Bug: txtone is %04x" % _mem.txtone)

        if _mem.rxtone in [0, 0xFFFF]:
            rxmode = ""
        elif _mem.rxtone >= 0x0258:
            rxmode = "Tone"
            mem.ctone = int(_mem.rxtone) / 10.0
        elif _mem.rxtone <= 0x0258:
            rxmode = "DTCS"
            if _mem.rxtone >= 0x6A:
                index = _mem.rxtone - 0x6A
                dtcs_pol[1] = "R"
            else:
                index = _mem.rxtone - 1
            mem.rx_dtcs = SHX8800_DTCS[index]
        else:
            LOG.warn("Bug: rxtone is %04x" % _mem.rxtone)

        if txmode == "Tone" and not rxmode:
            mem.tmode = "Tone"
        elif txmode == rxmode and txmode == "Tone" and mem.rtone == mem.ctone:
            mem.tmode = "TSQL"
        elif txmode == rxmode and txmode == "DTCS" and mem.dtcs == mem.rx_dtcs:
            mem.tmode = "DTCS"
        elif rxmode or txmode:
            mem.tmode = "Cross"
            mem.cross_mode = "%s->%s" % (txmode, rxmode)

        mem.dtcs_polarity = "".join(dtcs_pol)

        if not _mem.scan:
            mem.skip = "S"

        mem.power = SHX8800_POWER_LEVELS[_mem.power_lvl]

        mem.mode = _mem.narrow and "NFM" or "FM"

        mem.extra = RadioSettingGroup("Extra", "extra")

        rs = RadioSetting("busy_lock", "Busy lock",
                          RadioSettingValueBoolean(_mem.busy_lock))
        mem.extra.append(rs)

        rs = RadioSetting("pttid", "PTT ID",
                          RadioSettingValueList(PTTID_LIST,
                                                PTTID_LIST[_mem.pttid]))
        mem.extra.append(rs)

        rs = RadioSetting("scode", "PTT ID Code",
                          RadioSettingValueList(PTTIDCODE_LIST,
                                                PTTIDCODE_LIST[_mem.scode]))
        mem.extra.append(rs)

        return mem

    def _set_mem(self, number):
        return self._memobj.memory[number]

    def _set_nam(self, number):
        return self._memobj.names[number]

    def set_memory(self, mem):
        _mem = self._get_mem(mem.number)
        _nam = self._get_nam(mem.number)

        if mem.empty:
            _mem.set_raw("\xff" * 16)
            _nam.set_raw("\xff" * 16)
            return

        was_empty = False
        # same method as used in get_memory to find
        # out whether a raw memory is empty
        if _mem.get_raw()[0] == "\xff":
            was_empty = True
            LOG.debug("SenHaiX 8800: this mem was empty")
        else:
            # memorize old extra-values before erasing the whole memory
            # used to solve issue 4121
            LOG.debug("mem was not empty, memorize extra-settings")
            prev_busy_lock = _mem.busy_lock.get_value()
            prev_scode = _mem.scode.get_value()
            prev_pttid = _mem.pttid.get_value()

        _mem.set_raw("\x00" * 16)

        # CHIRP entry shoud always have emission enabled
        _mem.allow_emission = 1

        _mem.rxfreq = mem.freq / 10

        if mem.duplex == "off":
            for i in range(0, 4):
                _mem.txfreq[i].set_raw("\xFF")
        elif mem.duplex == "split":
            _mem.txfreq = mem.offset / 10
        elif mem.duplex == "+":
            _mem.txfreq = (mem.freq + mem.offset) / 10
        elif mem.duplex == "-":
            _mem.txfreq = (mem.freq - mem.offset) / 10
        else:
            _mem.txfreq = mem.freq / 10

        _namelength = self.get_features().valid_name_length
        for i in range(_namelength):
            try:
                _nam.name[i] = mem.name[i]
            except IndexError:
                _nam.name[i] = "\xFF"

        rxmode = txmode = ""
        if mem.tmode == "Tone":
            _mem.txtone = int(mem.rtone * 10)
            _mem.rxtone = 0
        elif mem.tmode == "TSQL":
            _mem.txtone = int(mem.ctone * 10)
            _mem.rxtone = int(mem.ctone * 10)
        elif mem.tmode == "DTCS":
            rxmode = txmode = "DTCS"
            _mem.txtone = SHX8800_DTCS.index(mem.dtcs) + 1
            _mem.rxtone = SHX8800_DTCS.index(mem.dtcs) + 1
        elif mem.tmode == "Cross":
            txmode, rxmode = mem.cross_mode.split("->", 1)
            if txmode == "Tone":
                _mem.txtone = int(mem.rtone * 10)
            elif txmode == "DTCS":
                _mem.txtone = SHX8800_DTCS.index(mem.dtcs) + 1
            else:
                _mem.txtone = 0
            if rxmode == "Tone":
                _mem.rxtone = int(mem.ctone * 10)
            elif rxmode == "DTCS":
                _mem.rxtone = SHX8800_DTCS.index(mem.rx_dtcs) + 1
            else:
                _mem.rxtone = 0
        else:
            _mem.rxtone = 0
            _mem.txtone = 0

        if txmode == "DTCS" and mem.dtcs_polarity[0] == "R":
            _mem.txtone += 0x69
        if rxmode == "DTCS" and mem.dtcs_polarity[1] == "R":
            _mem.rxtone += 0x69

        _mem.scan = mem.skip != "S"
        _mem.narrow = mem.mode == "NFM"
        _mem.power_lvl = SHX8800_POWER_LEVELS.index(mem.power)

        if not was_empty:
            # restoring old extra-settings
            _mem.busy_lock.set_value(prev_busy_lock)
            _mem.scode.set_value(prev_scode)
            _mem.pttid.set_value(prev_pttid)

        for setting in mem.extra:
            setattr(_mem, setting.get_name(), setting.value)

    @classmethod
    def match_model(cls, filedata, filename):
        return True

    def get_raw_memory(self, number):
        return repr(self._memobj.memory[number])
