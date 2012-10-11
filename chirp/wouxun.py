# Copyright 2011 Dan Smith <dsmith@danplanet.com>
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

import struct
import time
import os
from chirp import util, chirp_common, bitwise, memmap, errors, directory
from chirp.settings import RadioSetting, RadioSettingGroup, \
                RadioSettingValueBoolean, RadioSettingValueList

if os.getenv("CHIRP_DEBUG"):
    DEBUG = True
else:
    DEBUG = False

def wipe_memory(_mem, byte):
    _mem.set_raw(byte * (_mem.size() / 8))

@directory.register
class KGUVD1PRadio(chirp_common.CloneModeRadio):
    """Wouxun KG-UVD1P,UV2,UV3"""
    VENDOR = "Wouxun"
    MODEL = "KG-UVD1P"
    _model = "KG669V"
    
    _querymodel = "HiWOUXUN\x02"
    
    CHARSET = list("0123456789") + [chr(x + ord("A")) for x in range(0, 26)] + \
        list("?+-")

    POWER_LEVELS = [chirp_common.PowerLevel("High", watts=5.00),
                    chirp_common.PowerLevel("Low", watts=1.00)]


    _MEM_FORMAT = """
        #seekto 0x0010;
        struct {
          lbcd rx_freq[4];
          lbcd tx_freq[4];
          ul16 rx_tone;
          ul16 tx_tone;
          u8 _3_unknown_1:4,
             bcl:1,
             _3_unknown_2:3;
          u8 splitdup:1,
             skip:1,
             power_high:1,
             iswide:1,
             _2_unknown_2:4;
          u8 unknown[2];
        } memory[199];

        #seekto 0x0E5C;
        struct {
          u8 unknown_flag1:7,
             menu_available:1;
        } settings;

        #seekto 0x1008;
        struct {
          u8 unknown[8];
          u8 name[6];
          u8 pad[2];
        } names[199];
    """

    def _identify(self):
        """Do the original wouxun identification dance"""
        for _i in range(0, 5):
            self.pipe.write(_querymodel)
            resp = self.pipe.read(9)
            if len(resp) != 9:
                print "Got:\n%s" % util.hexprint(resp)
                print "Retrying identification..."
                time.sleep(1)
                continue
            if resp[2:8] != self._model:
                raise Exception("I can't talk to this model (%s)" % util.hexprint(resp))
            return
        if len(resp) == 0:
            raise Exception("Radio not responding")
        else:
            raise Exception("Unable to identify radio")

    def _start_transfer(self):
        """Tell the radio to go into transfer mode"""
        self.pipe.write("\x02\x06")
        time.sleep(0.05)
        ack = self.pipe.read(1)
        if ack != "\x06":
            raise Exception("Radio refused transfer mode")    

    def _do_download(self, start, end, blocksize):
        """Initiate a download of @radio between @start and @end"""
        image = ""
        for i in range(start, end, blocksize):
            cmd = struct.pack(">cHb", "R", i, blocksize)
            if DEBUG:
                print util.hexprint(cmd)
            self.pipe.write(cmd)
            length = len(cmd) + blocksize
            resp = self.pipe.read(length)
            if len(resp) != (len(cmd) + blocksize):
                print util.hexprint(resp)
                raise Exception("Failed to read full block (%i!=%i)" % \
                                    (len(resp),
                                     len(cmd) + blocksize))
            
            self.pipe.write("\x06")
            self.pipe.read(1)
            image += resp[4:]

            if self.status_fn:
                status = chirp_common.Status()           
                status.cur = i
                status.max = end
                status.msg = "Cloning from radio"
                self.status_fn(status)
        
        return memmap.MemoryMap(image)

    def _do_upload(self, start, end, blocksize):
        """Initiate an upload of @radio between @start and @end"""
        ptr = start
        for i in range(start, end, blocksize):
            cmd = struct.pack(">cHb", "W", i, blocksize)
            chunk = self.get_mmap()[ptr:ptr+blocksize]
            ptr += blocksize
            self.pipe.write(cmd + chunk)
            if DEBUG:
                print util.hexprint(cmd + chunk)

            ack = self.pipe.read(1)
            if not ack == "\x06":
                raise Exception("Radio did not ack block %i" % ptr)
            #radio.pipe.write(ack)

            if self.status_fn:
                status = chirp_common.Status()
                status.cur = i
                status.max = end
                status.msg = "Cloning to radio"
                self.status_fn(status)

    def _download(self):
        """Talk to an original wouxun and do a download"""
        try:
            self._identify()
            self._start_transfer()
            return self._do_download(0x0000, 0x2000, 0x0040)
        except errors.RadioError:
            raise
        except Exception, e:
            raise errors.RadioError("Failed to communicate with radio: %s" % e)

    def _upload(self):
        """Talk to an original wouxun and do an upload"""
        try:
            self._identify()
            self._start_transfer()
            return self._do_upload(0x0000, 0x2000, 0x0010)
        except errors.RadioError:
            raise
        except Exception, e:
            raise errors.RadioError("Failed to communicate with radio: %s" % e)


    def sync_in(self):
        self._mmap = self._download()
        self.process_mmap()

    def sync_out(self):
        self._upload()

    def process_mmap(self):
        if len(self._mmap.get_packed()) != 8192:
            print "NOTE: Fixing old-style Wouxun image"
            # Originally, CHIRP's wouxun image had eight bytes of
            # static data, followed by the first memory at offset
            # 0x0008.  Between 0.1.11 and 0.1.12, this was fixed to 16
            # bytes of (whatever) followed by the first memory at
            # offset 0x0010, like the radio actually stores it.  So,
            # if we find one of those old ones, convert it to the new
            # format, padding 16 bytes of 0xFF in front.
            self._mmap = memmap.MemoryMap(("\xFF" * 16) + \
                                              self._mmap.get_packed()[8:8184])
        self._memobj = bitwise.parse(self._MEM_FORMAT, self._mmap)

    def get_features(self):
        rf = chirp_common.RadioFeatures()
        rf.valid_tmodes = ["", "Tone", "TSQL", "DTCS", "Cross"]
        rf.valid_cross_modes = [
                        "Tone->Tone",
                        "Tone->DTCS",
                        "DTCS->Tone",
                        "DTCS->",
                        "->Tone",
                        "->DTCS",
                        "DTCS->DTCS",
                    ]
        rf.valid_modes = ["FM", "NFM"]
        rf.valid_power_levels = self.POWER_LEVELS
        rf.valid_bands = [(136000000, 174000000), (216000000, 520000000)]
        rf.valid_characters = "".join(self.CHARSET)
        rf.valid_name_length = 6
        rf.valid_duplexes = ["", "+", "-", "split"]
        rf.has_ctone = True
        rf.has_rx_dtcs = True
        rf.has_cross = True
        rf.has_tuning_step = False
        rf.has_bank = False
        rf.has_settings = True
        rf.memory_bounds = (1, 128)
        rf.can_odd_split = True
        return rf

    def get_settings(self):
        group = RadioSettingGroup("top", "All Settings")

        rs = RadioSetting("menu_available", "Menu Available",
                          RadioSettingValueBoolean(self._memobj.settings.menu_available))
        group.append(rs)

        return group

    def set_settings(self, settings):
        for element in settings:
            if not isinstance(element, RadioSetting):
                self.set_settings(element)
                continue
            try:
                setattr(self._memobj.settings, element.get_name(), element.value)
            except Exception, e:
                print element.get_name()
                raise



    def get_raw_memory(self, number):
        return repr(self._memobj.memory[number - 1])

    def _get_tone(self, _mem, mem):
        def _get_dcs(val):
            code = int("%03o" % (val & 0x07FF))
            pol = (val & 0x8000) and "R" or "N"
            return code, pol
            
        if _mem.tx_tone != 0xFFFF and _mem.tx_tone > 0x2800:
            tcode, tpol = _get_dcs(_mem.tx_tone)
            mem.dtcs = tcode
            txmode = "DTCS"
        elif _mem.tx_tone != 0xFFFF:
            mem.rtone = _mem.tx_tone / 10.0
            txmode = "Tone"
        else:
            txmode = ""

        if _mem.rx_tone != 0xFFFF and _mem.rx_tone > 0x2800:
            rcode, rpol = _get_dcs(_mem.rx_tone)
            mem.rx_dtcs = rcode
            rxmode = "DTCS"
        elif _mem.rx_tone != 0xFFFF:
            mem.ctone = _mem.rx_tone / 10.0
            rxmode = "Tone"
        else:
            rxmode = ""

        if txmode == "Tone" and not rxmode:
            mem.tmode = "Tone"
        elif txmode == rxmode and txmode == "Tone" and mem.rtone == mem.ctone:
            mem.tmode = "TSQL"
        elif txmode == rxmode and txmode == "DTCS" and mem.dtcs == mem.rx_dtcs:
            mem.tmode = "DTCS"
        elif rxmode or txmode:
            mem.tmode = "Cross"
            mem.cross_mode = "%s->%s" % (txmode, rxmode)

        if mem.tmode == "DTCS":
            mem.dtcs_polarity = "%s%s" % (tpol, rpol)

        if DEBUG:
            print "Got TX %s (%i) RX %s (%i)" % (txmode, _mem.tx_tone,
                                                 rxmode, _mem.rx_tone)

    def get_memory(self, number):
        _mem = self._memobj.memory[number - 1]
        _nam = self._memobj.names[number - 1]

        mem = chirp_common.Memory()
        mem.number = number

        if _mem.get_raw() == ("\xff" * 16):
            mem.empty = True
            return mem

        mem.freq = int(_mem.rx_freq) * 10
        if _mem.splitdup:
            mem.duplex = "split"
        elif int(_mem.rx_freq) < int(_mem.tx_freq):
            mem.duplex = "+"
        elif int(_mem.rx_freq) > int(_mem.tx_freq):
            mem.duplex = "-"

        if mem.duplex == "":
            mem.offset = 0
        elif mem.duplex == "split":
            mem.offset = int(_mem.tx_freq) * 10
        else:
            mem.offset = abs(int(_mem.tx_freq) - int(_mem.rx_freq)) * 10

        if not _mem.skip:
            mem.skip = "S"
        if not _mem.iswide:
            mem.mode = "NFM"

        self._get_tone(_mem, mem)

        mem.power = self.POWER_LEVELS[not _mem.power_high]

        for i in _nam.name:
            if i == 0xFF:
                break
            mem.name += self.CHARSET[i]

        mem.extra = RadioSettingGroup("Extra", "extra")
        bcl = RadioSetting("BCL", "bcl",
                           RadioSettingValueBoolean(bool(_mem.bcl)))
        bcl.set_doc("Busy Channel Lockout")
        mem.extra.append(bcl)

        return mem

    def _set_tone(self, mem, _mem):
        def _set_dcs(code, pol):
            val = int("%i" % code, 8) + 0x2800
            if pol == "R":
                val += 0xA000
            return val

        if mem.tmode == "Cross":
            tx_mode, rx_mode = mem.cross_mode.split("->")
        elif mem.tmode == "Tone":
            tx_mode = mem.tmode
            rx_mode = None
        else:
            tx_mode = rx_mode = mem.tmode


        if tx_mode == "DTCS":
            _mem.tx_tone = mem.tmode != "DTCS" and \
                _set_dcs(mem.dtcs, mem.dtcs_polarity[0]) or _set_dcs(mem.rx_dtcs, mem.dtcs_polarity[0])
        elif tx_mode:
            _mem.tx_tone = tx_mode == "Tone" and \
                int(mem.rtone * 10) or int(mem.ctone * 10)
        else:
            _mem.tx_tone = 0xFFFF

        if rx_mode == "DTCS":
            _mem.rx_tone = _set_dcs(mem.rx_dtcs, mem.dtcs_polarity[1])
        elif rx_mode:
            _mem.rx_tone = int(mem.ctone * 10)
        else:
            _mem.rx_tone = 0xFFFF

        if DEBUG:
            print "Set TX %s (%i) RX %s (%i)" % (tx_mode, _mem.tx_tone,
                                                 rx_mode, _mem.rx_tone)

    def set_memory(self, mem):
        _mem = self._memobj.memory[mem.number - 1]
        _nam = self._memobj.names[mem.number - 1]

        if mem.empty:
            wipe_memory(_mem, "\xFF")
            return

        if _mem.get_raw() == ("\xFF" * 16):
            wipe_memory(_mem, "\x00")

        _mem.rx_freq = int(mem.freq / 10)
        if mem.duplex == "split":
            _mem.tx_freq = int(mem.offset / 10)
        elif mem.duplex == "+":
            _mem.tx_freq = int(mem.freq / 10) + int(mem.offset / 10)
        elif mem.duplex == "-":
            _mem.tx_freq = int(mem.freq / 10) - int(mem.offset / 10)
        else:
            _mem.tx_freq = int(mem.freq / 10)
        _mem.splitdup = mem.duplex == "split"
        _mem.skip = mem.skip != "S"
        _mem.iswide = mem.mode != "NFM"

        self._set_tone(mem, _mem)

        if mem.power:
            _mem.power_high = not self.POWER_LEVELS.index(mem.power)
        else:
            _mem.power_high = True

        _nam.name = [0xFF] * 6
        for i in range(0, len(mem.name)):
            try:
                _nam.name[i] = self.CHARSET.index(mem.name[i])
            except IndexError:
                raise Exception("Character `%s' not supported")

        for setting in mem.extra:
            setattr(_mem, setting.get_shortname(), setting.value)

    @classmethod
    def match_model(cls, filedata, filename):
        # New-style image (CHIRP 0.1.12)
        if len(filedata) == 8192 and \
                filedata[0x60:0x64] != "2009" and \
                filedata[0x1f77:0x1f7d] == "\xff\xff\xff\xff\xff\xff": # that area is (seems to be) unused
            return True
        # Old-style image (CHIRP 0.1.11)
        if len(filedata) == 8200 and \
                filedata[0:4] == "\x01\x00\x00\x00":
            return True
        return False

@directory.register
class KGUV6DRadio(KGUVD1PRadio):
    MODEL = "KG-UV6"
    
    _querymodel = "HiWXUVD1\x02"
    
    _MEM_FORMAT = """
        #seekto 0x0010;
        struct {
          lbcd rx_freq[4];
          lbcd tx_freq[4];
          ul16 rx_tone;
          ul16 tx_tone;
          u8 _3_unknown_1:4,
             bcl:1,
             _3_unknown_2:3;
          u8 splitdup:1,
             skip:1,
             power_high:1,
             iswide:1,
             _2_unknown_2:4;
          u8 unknown[2];
        } memory[199];

        #seekto 0x0F00;
        struct {
          u8 unknown1[44];
          u8 unknown_flag1:6,
             voice:2;
          u8 unknown_flag2:7,
             beep:1;
          u8 unknown2[12];
          u8 unknown_flag3:6,
             ponmsg:2;
          u8 unknown3[3];
          u8 unknown_flag4:7,
             sos_ch:1;
          u8 unknown4[29];
          u8 unknown_flag5:7,
             menu_available:1;
        } settings;

        #seekto 0x1008;
        struct {
          u8 unknown[8];
          u8 name[6];
          u8 pad[2];
        } names[199];
    """


    def get_features(self):
        rf = KGUVD1PRadio.get_features(self)
        rf.valid_bands = [(136000000, 175000000), (350000000, 471000000)]
        rf.memory_bounds = (1, 199)
        return rf

    def get_settings(self):
        group = RadioSettingGroup("top", "All Settings")

        rs = RadioSetting("menu_available", "Menu Available",
                          RadioSettingValueBoolean(self._memobj.settings.menu_available))
        group.append(rs)
        rs = RadioSetting("beep", "Beep",
                          RadioSettingValueBoolean(self._memobj.settings.beep))
        group.append(rs)
        options = ["Off", "Welcome", "V bat"]
        rs = RadioSetting("ponmsg", "PONMSG",
                          RadioSettingValueList(options,
                                            options[self._memobj.settings.ponmsg]))
        group.append(rs)
        options = ["Off", "Chinese", "English"]
        rs = RadioSetting("voice", "Voice",
                          RadioSettingValueList(options,
                                            options[self._memobj.settings.voice]))
        group.append(rs)
        options = ["CH A", "CH B"]
        rs = RadioSetting("sos_ch", "SOS CH",
                          RadioSettingValueList(options,
                                            options[self._memobj.settings.sos_ch]))
        group.append(rs)


        return group

    def set_settings(self, settings):
        for element in settings:
            if not isinstance(element, RadioSetting):
                self.set_settings(element)
                continue
            try:
                setattr(self._memobj.settings, element.get_name(), element.value)
            except Exception, e:
                print element.get_name()
                raise

    @classmethod
    def match_model(cls, filedata, filename):
        if len(filedata) == 8192 and \
                filedata[0x1f77:0x1f7d] == "WELCOM":
            return True
        return False
