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
                RadioSettingValueFloat, RadioSettingValueMap, RadioSettings

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
     bcl:1,
     scan:1,
     allow_tx:1,
     fhss:1;
} memory[128];

#seekto 0xc00;
struct {
  char name[16];
} names[128];

#seekto 0x1a00;
struct {
  u8 squelch;
  u8 battery_saver;
  u8 vox;
  u8 auto_bl;
  u8 tdr;
  u8 tot;
  u8 beep;
  u8 voice;
  u8 language;
  u8 dtmfst;
  u8 scan_mode;
  u8 pttid;
  u8 pttlt;
  u8 mdfa;
  u8 mdfb;
  u8 bcl;

  u8 autolk;
  u8 almod;
  u8 alsnd;
  u8 tx_under_tdr_start;
  u8 ste;
  u8 rpste;
  u8 rptrl;
  u8 roger;
  u8 unknown;
  u8 fmradio;
  u8 workmodeb:4,
     workmodea:4;
  u8 keylock;
  u8 unknown1[4];

  u8 voxdelay;
  u8 menu_timeout;
  u8 micgain;
} settings;

#seekto 0x1a40;
struct {
  u8 freq[8];
  ul16 rxtone;
  ul16 txtone;
  u8 unknown[2];
  u8 unused2:2,
     sftd:2,
     scode:4;
  u8 unknown1;
  u8 txpower;
  u8 widenarr:1,
     unknown2:4
     fhss:1;
  u8 band;
  u8 unknown3:5,
     step:3;
  u8 unknown4;
  u8 offset[6];
} vfoa;

#seekto 0x1a60;
struct {
  u8 freq[8];
  ul16 rxtone;
  ul16 txtone;
  u8 unknown[2];
  u8 unused2:2,
     sftd:2,
     scode:4;
  u8 unknown1;
  u8 txpower;
  u8 widenarr:1,
     unknown2:4
     fhss:1;
  u8 band;
  u8 unknown3:5,
     step:3;
  u8 unknown4;
  u8 offset[6];
} vfob;

#seekto 0x1a80;
struct {
    u8 sidekey;
    u8 sidekeyl;
} keymaps;

#seekto 0x1b00;
struct {
  u8 code[5];
  u8 unused[11];
} pttid[15];

struct {
  u8 code[5];
  u8 group_code;
  u8 aniid;
  u8 dtmfon;
  u8 dtmfoff;
} ani;

"""

SHX8800_POWER_LEVELS = [chirp_common.PowerLevel("High", watts=5.00),
                     chirp_common.PowerLevel("Low",  watts=1.00)]

SHX8800_DTCS = sorted(chirp_common.DTCS_CODES + [645])

AUTOBL_LIST = ["OFF", "5 sec", "10 sec", "15 sec", "20 sec", "30 sec", "1 min", "2 min", "3 min"]
TOT_LIST = ["OFF"] + ["%s sec" % x for x in range(30, 270, 30)]
VOX_LIST = ["OFF"] + ["%s" % x for x in range(1, 4)]
BANDWIDTH_LIST = ["Wide", "Narrow"]
LANGUAGE_LIST = ["English", "Chinese"]
DTMFST_LIST = ["OFF", "DT-ST", "ANI-ST", "DT+ANI"]
SCAN_MODE_LIST = ["TO", "CO", "SE"]
PTTID_LIST = ["OFF", "BOT", "EOT", "Both"]
PTTLT_LIST = ["%s ms" % x for x in range(0, 31)]
MODE_LIST = ["CH + Name", "CH + Frequency"]
ALMOD_LIST = ["SITE", "TOME", "CODE"]
RPSTE_LIST = ["OFF"] + ["%s" % x for x in range(1, 11)]
STEDELAY_LIST = ["%s ms" % x for x in range(0, 1100, 100)]
WORKMODE_LIST = ["VFO", "CH"]
VOX_DELAY_LIST = ["%s ms" % x for x in range(500, 2100, 100)]
MENU_TIMEOUT_LIST = ["%s sec" % x for x in range(5, 65, 5)]
MICGAIN_LIST = ["%s" % x for x in range(1, 6, 1)]
DTMFSPEED_LIST = ["%s ms" % x for x in range(50, 550, 50)]
PTTIDCODE_LIST = ["%s" % x for x in range(1, 16)]
STEPS = [2.5, 5.0, 6.25, 10.0, 12.5, 25.0]
STEP_LIST = [str(x) for x in STEPS]
TXPOWER_LIST = ["High", "Low"]
SHIFTD_LIST = ["Off", "+", "-"]
KEY_FUNCTIONS = [("Monitor", 5), ("Broadcast FM Radio", 7), ("Tx Power Switch", 10), ("Scan", 28), ("Match", 29)]


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

        rf.valid_bands = [(100000000, 176000000), (400000000, 521000000)]
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
        return _mem.allow_tx == False

    def _get_mem(self, number):
        return self._memobj.memory[number]

    def _get_nam(self, number):
        return self._memobj.names[number]

    def get_raw_memory(self, number):
        return repr(self._memobj.memory[number])

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

        rs = RadioSetting("bcl", "bcl",
                          RadioSettingValueBoolean(_mem.bcl))
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
            LOG.debug("mem was not empty, memorize extra-settings")
            prev_bcl = _mem.bcl.get_value()
            prev_scode = _mem.scode.get_value()
            prev_pttid = _mem.pttid.get_value()

        _mem.set_raw("\x00" * 16)

        _mem.rxfreq = mem.freq / 10

        _mem.allow_tx = True
        if mem.duplex == "off":
            _mem.allow_tx = False
            _mem.txfreq = mem.offset / 10
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
            _mem.bcl.set_value(prev_bcl)
            _mem.scode.set_value(prev_scode)
            _mem.pttid.set_value(prev_pttid)

        for setting in mem.extra:
            setattr(_mem, setting.get_name(), setting.value)

    def _get_settings(self):
        _ani = self._memobj.ani
        _settings = self._memobj.settings
        _vfoa = self._memobj.vfoa
        _vfob = self._memobj.vfob
        _keymaps = self._memobj.keymaps

        basic = RadioSettingGroup("basic", "Basic Settings")
        advanced = RadioSettingGroup("advanced", "Advanced Settings")
        workmode = RadioSettingGroup("workmode", "Work Mode Settings")
        keymaps = RadioSettingGroup("keymaps", "KeyMaps")
        dtmf = RadioSettingGroup("dtmf", "DTMF Settings")

        group = RadioSettings(basic, advanced, workmode, keymaps, dtmf)

        rs = RadioSetting("squelch", "Carrier Squelch Level",
                          RadioSettingValueInteger(0, 5, _settings.squelch))
        basic.append(rs)

        rs = RadioSetting("battery_saver", "Battery Save",
                        RadioSettingValueBoolean(_settings.battery_saver))
        advanced.append(rs)

        rs = RadioSetting("vox", "VOX Sensitivity",
                          RadioSettingValueList(
                          VOX_LIST, VOX_LIST[_settings.vox]))
        basic.append(rs)

        rs = RadioSetting("auto_bl", "Auto Backlight Timeout",
                          RadioSettingValueList(
                              AUTOBL_LIST, AUTOBL_LIST[_settings.auto_bl]))
        advanced.append(rs)

        rs = RadioSetting("tot", "TX Timeout Timer",
                          RadioSettingValueList(
                              TOT_LIST, TOT_LIST[_settings.tot]))
        basic.append(rs)

        rs = RadioSetting("beep", "Beep",
                          RadioSettingValueBoolean(_settings.beep))
        basic.append(rs)

        rs = RadioSetting("voice", "Voice",
                          RadioSettingValueBoolean(_settings.voice))
        advanced.append(rs)

        rs = RadioSetting("language", "Language",
                          RadioSettingValueList(
                          LANGUAGE_LIST, LANGUAGE_LIST[_settings.language]))
        advanced.append(rs)

        rs = RadioSetting("mdfa", "Display Mode (A)",
                            RadioSettingValueList(
                            MODE_LIST, MODE_LIST[_settings.mdfa]))
        basic.append(rs)

        rs = RadioSetting("mdfb", "Display Mode (B)",
                            RadioSettingValueList(
                            MODE_LIST, MODE_LIST[_settings.mdfb]))
        basic.append(rs)

        rs = RadioSetting("scan_mode", "Scan Mode",
                            RadioSettingValueList(
                            SCAN_MODE_LIST, SCAN_MODE_LIST[_settings.scan_mode]))
        basic.append(rs)

        rs = RadioSetting("bcl", "Busy Channel Lockout",
                          RadioSettingValueBoolean(_settings.bcl))
        advanced.append(rs)

        rs = RadioSetting("autolk", "Automatic Key Lock",
                            RadioSettingValueBoolean(_settings.autolk))
        advanced.append(rs)

        rs = RadioSetting("almod", "Alarm Mode",
                          RadioSettingValueList(
                            ALMOD_LIST, ALMOD_LIST[_settings.almod]))
        advanced.append(rs)

        rs = RadioSetting("alsnd", "Alarm Sound",
                          RadioSettingValueBoolean(_settings.alsnd))
        advanced.append(rs)

        rs = RadioSetting("ste", "Squelch Tail Eliminate (HT to HT)",
                          RadioSettingValueBoolean(_settings.ste))
        advanced.append(rs)

        rs = RadioSetting("rpste", "Squelch Tail Eliminate (repeater)",
                          RadioSettingValueList(
                              RPSTE_LIST, RPSTE_LIST[_settings.rpste]))
        advanced.append(rs)

        rs = RadioSetting("rptrl", "STE Repeater Delay",
                          RadioSettingValueList(
                              STEDELAY_LIST, STEDELAY_LIST[_settings.rptrl]))
        advanced.append(rs)

        rs = RadioSetting("fmradio", "Disable Broadcast FM Radio",
                          RadioSettingValueBoolean(_settings.fmradio))
        advanced.append(rs)

        rs = RadioSetting("keylock", "Keypad Lock",
                            RadioSettingValueBoolean(_settings.keylock))
        advanced.append(rs)

        rs = RadioSetting("voxdelay", "VOX Delay",
                            RadioSettingValueList(
                               VOX_DELAY_LIST,
                               VOX_DELAY_LIST[_settings.voxdelay]))
        advanced.append(rs)

        rs = RadioSetting("menu_timeout", "Menu Timeout",
                            RadioSettingValueList(
                               MENU_TIMEOUT_LIST,
                               MENU_TIMEOUT_LIST[_settings.menu_timeout]))
        advanced.append(rs)

        rs = RadioSetting("micgain", "Mic Gain",
                            RadioSettingValueList(
                               MICGAIN_LIST,
                               MICGAIN_LIST[_settings.micgain]))
        advanced.append(rs)

        rs = RadioSetting("keymaps.sidekey", "Side Key Short Press",
                           RadioSettingValueMap(KEY_FUNCTIONS, _keymaps.sidekey))
        keymaps.append(rs)

        rs = RadioSetting("keymaps.sidekeyl", "Side Key Long Press",
                           RadioSettingValueMap(KEY_FUNCTIONS, _keymaps.sidekeyl))
        keymaps.append(rs)

        rs = RadioSetting("workmodea", "Work Mode (A)",
                            RadioSettingValueList(
                                WORKMODE_LIST,
                                WORKMODE_LIST[_settings.workmodea]))
        workmode.append(rs)

        rs = RadioSetting("workmodeb", "Work Mode (B)",
                            RadioSettingValueList(
                                WORKMODE_LIST,
                                WORKMODE_LIST[_settings.workmodeb]))
        workmode.append(rs)

        def convert_bytes_to_freq(bytes):
            real_freq = 0
            for byte in bytes:
                real_freq = (real_freq * 10) + byte
            return chirp_common.format_freq(real_freq * 10)

        def my_validate(value):
            value = chirp_common.parse_freq(value)
            if 17400000 <= value and value < 40000000:
                msg = ("Can't be between 174.00000-400.00000")
                raise InvalidValueError(msg)
            return chirp_common.format_freq(value)

        def apply_freq(setting, obj):
            value = chirp_common.parse_freq(str(setting.value)) / 10
            obj.band = value >= 40000000
            for i in range(7, -1, -1):
                obj.freq[i] = value % 10
                value /= 10

        val1a = RadioSettingValueString(0, 10,
                                        convert_bytes_to_freq(_vfoa.freq))
        val1a.set_validate_callback(my_validate)
        rs = RadioSetting("vfoa.freq", "VFO A Frequency", val1a)
        rs.set_apply_callback(apply_freq, _vfoa)
        workmode.append(rs)

        val1b = RadioSettingValueString(0, 10,
                                        convert_bytes_to_freq(_vfob.freq))
        val1b.set_validate_callback(my_validate)
        rs = RadioSetting("vfob.freq", "VFO B Frequency", val1b)
        rs.set_apply_callback(apply_freq, _vfob)
        workmode.append(rs)

        rs = RadioSetting("vfoa.sftd", "VFO A Shift",
                            RadioSettingValueList(
                                SHIFTD_LIST, SHIFTD_LIST[_vfoa.sftd]))
        workmode.append(rs)

        rs = RadioSetting("vfob.sftd", "VFO B Shift",
                            RadioSettingValueList(
                                SHIFTD_LIST, SHIFTD_LIST[_vfob.sftd]))
        workmode.append(rs)

        def convert_bytes_to_offset(bytes):
            real_offset = 0
            for byte in bytes:
                real_offset = (real_offset * 10) + byte
            return chirp_common.format_freq(real_offset * 100)

        def apply_offset(setting, obj):
            value = chirp_common.parse_freq(str(setting.value)) / 100
            for i in range(5, -1, -1):
                obj.offset[i] = value % 10
                value /= 10

        val1a = RadioSettingValueString(
            0, 10, convert_bytes_to_offset(_vfoa.offset))
        rs = RadioSetting("vfoa.offset",
                            "VFO A Offset (0.0-999.999)", val1a)
        rs.set_apply_callback(apply_offset, _vfoa)
        workmode.append(rs)

        val1b = RadioSettingValueString(
            0, 10, convert_bytes_to_offset(_vfob.offset))
        rs = RadioSetting("vfob.offset",
                            "VFO B Offset (0.0-999.999)", val1b)
        rs.set_apply_callback(apply_offset, _vfob)
        workmode.append(rs)

        rs = RadioSetting("vfoa.txpower", "VFO A Power",
                            RadioSettingValueList(
                                TXPOWER_LIST,
                                TXPOWER_LIST[_vfoa.txpower]))
        workmode.append(rs)

        rs = RadioSetting("vfob.txpower", "VFO B Power",
                            RadioSettingValueList(
                                TXPOWER_LIST,
                                TXPOWER_LIST[_vfob.txpower]))
        workmode.append(rs)

        rs = RadioSetting("vfoa.widenarr", "VFO A Bandwidth",
                            RadioSettingValueList(
                                BANDWIDTH_LIST,
                                BANDWIDTH_LIST[_vfoa.widenarr]))
        workmode.append(rs)

        rs = RadioSetting("vfob.widenarr", "VFO B Bandwidth",
                            RadioSettingValueList(
                                BANDWIDTH_LIST,
                                BANDWIDTH_LIST[_vfob.widenarr]))
        workmode.append(rs)

        rs = RadioSetting("vfoa.scode", "VFO A PTT-ID",
                            RadioSettingValueList(
                                PTTIDCODE_LIST, PTTIDCODE_LIST[_vfoa.scode]))
        workmode.append(rs)

        rs = RadioSetting("vfob.scode", "VFO B PTT-ID",
                            RadioSettingValueList(
                                PTTIDCODE_LIST, PTTIDCODE_LIST[_vfob.scode]))
        workmode.append(rs)

        rs = RadioSetting("vfoa.step", "VFO A Tuning Step",
                            RadioSettingValueList(
                                STEP_LIST, STEP_LIST[_vfoa.step]))
        workmode.append(rs)
        rs = RadioSetting("vfob.step", "VFO B Tuning Step",
                            RadioSettingValueList(
                                STEP_LIST, STEP_LIST[_vfob.step]))
        workmode.append(rs)

        dtmfchars = "0123456789 *#ABCD"

        for i in range(0, 15):
            _codeobj = self._memobj.pttid[i].code
            _code = "".join([dtmfchars[x] for x in _codeobj if int(x) < 0x1F])
            val = RadioSettingValueString(0, 5, _code, False)
            val.set_charset(dtmfchars)
            rs = RadioSetting("pttid/%i.code" % i,
                              "PTT ID Code %i" % (i + 1), val)

            def apply_code(setting, obj):
                code = []
                for j in range(0, 5):
                    try:
                        code.append(dtmfchars.index(str(setting.value)[j]))
                    except IndexError:
                        code.append(0xFF)
                obj.code = code
            rs.set_apply_callback(apply_code, self._memobj.pttid[i])
            dtmf.append(rs)

        rs = RadioSetting("ani.aniid", "ANI ID",
                          RadioSettingValueList(PTTID_LIST,
                                                PTTID_LIST[_ani.aniid]))
        dtmf.append(rs)

        _codeobj = self._memobj.ani.code
        _code = "".join([dtmfchars[x] for x in _codeobj if int(x) < 0x1F])
        val = RadioSettingValueString(0, 5, _code, False)
        val.set_charset(dtmfchars)
        rs = RadioSetting("ani.code", "ANI Code", val)

        def apply_code(setting, obj):
            code = []
            for j in range(0, 5):
                try:
                    code.append(dtmfchars.index(str(setting.value)[j]))
                except IndexError:
                    code.append(0xFF)
            obj.code = code
        rs.set_apply_callback(apply_code, _ani)
        dtmf.append(rs)

        rs = RadioSetting("dtmfst", "DTMF Sidetone",
                          RadioSettingValueList(DTMFST_LIST,
                                                DTMFST_LIST[_settings.dtmfst]))
        dtmf.append(rs)

        if _ani.dtmfon > 0xC3:
            val = 0x00
        else:
            val = _ani.dtmfon
        rs = RadioSetting("ani.dtmfon", "DTMF Speed (on)",
                          RadioSettingValueList(DTMFSPEED_LIST,
                                                DTMFSPEED_LIST[val]))
        dtmf.append(rs)

        if _ani.dtmfoff > 0xC3:
            val = 0x00
        else:
            val = _ani.dtmfoff
        rs = RadioSetting("ani.dtmfoff", "DTMF Speed (off)",
                          RadioSettingValueList(DTMFSPEED_LIST,
                                                DTMFSPEED_LIST[val]))
        dtmf.append(rs)

        rs = RadioSetting("pttlt", "PTT ID Delay",
                          RadioSettingValueList(
                          PTTLT_LIST, PTTLT_LIST[_settings.pttlt]))
        dtmf.append(rs)

        return group

    def get_settings(self):
        try:
            return self._get_settings()
        except:
            import traceback
            LOG.error("Failed to parse settings: %s", traceback.format_exc())
            return None

    def set_settings(self, settings):
        _settings = self._memobj.settings
        for element in settings:
            if not isinstance(element, RadioSetting):
                    self.set_settings(element)
                    continue
            else:
                try:
                    name = element.get_name()
                    if "." in name:
                        bits = name.split(".")
                        obj = self._memobj
                        for bit in bits[:-1]:
                            if "/" in bit:
                                bit, index = bit.split("/", 1)
                                index = int(index)
                                obj = getattr(obj, bit)[index]
                            else:
                                obj = getattr(obj, bit)
                        setting = bits[-1]
                    else:
                        obj = _settings
                        setting = element.get_name()

                    if element.has_apply_callback():
                        LOG.debug("Using apply callback")
                        element.run_apply_callback()
                    elif element.value.get_mutable():
                        LOG.debug("Setting %s = %s" % (setting, element.value))
                        setattr(obj, setting, element.value)
                except Exception, e:
                    LOG.debug(element.get_name())
                    raise


    @classmethod
    def match_model(cls, filedata, filename):
        if len(filedata) in [MEM_SIZE]:
            return True

        return False
