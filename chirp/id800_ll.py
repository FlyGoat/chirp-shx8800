#!/usr/bin/python
#
# Copyright 2008 Dan Smith <dsmith@danplanet.com>
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

from chirp import chirp_common, errors, util, icf
from chirp.memmap import MemoryMap

POS_FREQ_START =  0
POS_FREQ_END   =  3
POS_TSTEP      =  8
POS_NAME_START = 11
POS_NAME_END   = 19
POS_DUPX       =  6
POS_MODE       = 21
POS_TENB       = 10
POS_RTONE      =  5
POS_CTONE      =  6
POS_DTCS       =  7
POS_DTCS_POL   = 11
POS_DOFF_START =  3
POS_DOFF_END   =  5
POS_MYCALL     = 0x3220
POS_URCALL     = 0x3250
POS_RPTCALL    = 0x3570
POS_FLAGS      = 0x2bf4

MEM_LOC_SIZE  = 22
MEM_LOC_START = 0x20

ID800_TS = {
    0x0: 5.0,
    0xA: 6.25,
    0x1: 10.0,
    0x2: 12.5,
    0x3: 15,
    0x4: 20,
    0x5: 25,
    0x6: 30,
    0x7: 50,
    0x8: 100,
    0x9: 200,
}

ID800_MODES = {
    0x00 : "FM",
    0x10 : "NFM",
    0x20 : "AM",
    0x30 : "NAM",
    0x40 : "DV",
}

ID800_MODES_REV = {}
for val, mode in ID800_MODES.items():
    ID800_MODES_REV[mode] = val

def is_used(map, number):
    return not (ord(map[POS_FLAGS + number]) & 0x70)

def set_used(map, number, used):
    val = ord(map[POS_FLAGS + number]) & 0x0F

    if not used:
        val |= 0x70

    map[POS_FLAGS + number] = val

def get_name(map):
    nibbles = []

    for i in map[POS_NAME_START:POS_NAME_END]:
        nibbles.append((ord(i) & 0xF0) >> 4)
        nibbles.append(ord(i) & 0x0F)

    ln = None
    i = 1
    name = ""

    while i < len(nibbles) - 1:
        this = nibbles[i]

        if ln is None:
            i += 1
            ln = nibbles[i]
            this = (this << 2)  | ((ln >> 2) & 0x3)
        else:
            this = ((ln & 0x3) << 4) | this
            ln = None

        if this == 0:
            name += " "
        elif (this & 0x20) == 0:
            name += chr(ord("1") + (this & 0x0F) - 1)
        else:
            name += chr(ord("A") + (this & 0x1F) - 1)

        i += 1

    return name.rstrip()

def get_freq_ts(map):
    fval = '\x00' + map[POS_FREQ_START:POS_FREQ_END]
    tsval = (ord(map[POS_TSTEP]) >> 4) & 0x0F

    if tsval == 0xA or tsval == 0x2:
        mult = 6.25
    else:
        mult = 5.0

    freq = ((struct.unpack(">i", fval)[0] * mult) / 1000.0)
    

    return freq, ID800_TS.get(tsval, 5.0)

def get_duplex(map):
    val = struct.unpack("B", map[POS_DUPX])[0] & 0xC0
    if val == 0xC0:
        return "+"
    elif val == 0x80:
        return "-"
    else:
        return ""

def get_mode(map):
    val = struct.unpack("B", map[POS_MODE])[0] & 0x70
    try:
        return ID800_MODES[val]
    except KeyError:
        raise errors.InvalidDataError("Radio has invalid mode %02x" % mode)

def get_rtone(map):
    idx = struct.unpack("B", map[POS_RTONE])[0]
    
    return chirp_common.TONES[idx]

def get_ctone(map):
    idx = struct.unpack("B", map[POS_CTONE])[0] & 0x3F

    return chirp_common.TONES[idx]

def get_dtcs(map):
    idx = struct.unpack("B", map[POS_DTCS])[0]

    return chirp_common.DTCS_CODES[idx]

def get_tone_enabled(map):
    val = struct.unpack("B", map[POS_TENB])[0] & 0x03

    dtcs = tenc = tsql = False

    if val == 3:
        dtcs = True
    else:
        tenc = (val & 0x01) != 0
        tsql = (val & 0x02) != 0

    return tenc, tsql, dtcs

def get_dtcs_polarity(map):
    val = struct.unpack("B", map[POS_DTCS_POL])[0] & 0xC0

    pol_values = { 0x00 : "NN",
                   0x40 : "NR",
                   0x80 : "RN",
                   0xC0 : "RR" }

    return pol_values[val]        

def get_dup_offset(map):
    val = struct.unpack(">H", map[POS_DOFF_START:POS_DOFF_END])[0] & 0xEFFF

    return float(val * 5.0) / 1000.0

def get_mem_offset(number):
    return (number * MEM_LOC_SIZE) + MEM_LOC_START

def get_raw_memory(map, number):
    offset = get_mem_offset(number)
    return MemoryMap(map[offset:offset + MEM_LOC_SIZE])

def get_call_indices(map):
    return ord(map[18]), ord(map[19]), ord(map[20])

def get_memory(_map, number):
    if not is_used(_map, number):
        raise errors.InvalidMemoryLocation("Location %i is empty" % number)

    map = get_raw_memory(_map, number)

    if get_mode(map) == "DV":
        mem = chirp_common.DVMemory()
        i_ucall, i_r1call, i_r2call = get_call_indices(map)
        mem.UrCall = get_urcall(_map, i_ucall)
        mem.Rpt1Call = get_rptcall(_map, i_r1call)
        mem.Rpt2Call = get_rptcall(_map, i_r2call)
    else:
        mem = chirp_common.Memory()

    mem.freq, mem.tuningStep = get_freq_ts(map)
    mem.name = get_name(map)
    mem.number = number
    mem.duplex = get_duplex(map)
    mem.offset = get_dup_offset(map)
    mem.mode = get_mode(map)
    mem.rtone = get_rtone(map)
    mem.ctone = get_ctone(map)
    mem.dtcs = get_dtcs(map)
    mem.tencEnabled, mem.tsqlEnabled, mem.dtcsEnabled = get_tone_enabled(map)
    mem.dtcsPolarity = get_dtcs_polarity(map)

    return mem

def call_location(base, index):
    return base + (8 * (index - 1))

def get_mycall(map, index):
    if index > 7:
        raise errors.InvalidDataError("MYCALL index must be <= 7")

    start = call_location(POS_MYCALL, index)

    return map[start:start+8].strip()

def get_urcall(map, index):
    if index > 99:
        raise errors.InvalidDataError("URCALL index must be <= 99")

    start = call_location(POS_URCALL, index)

    return map[start:start+8].strip()

def get_rptcall(map, index):
    if index > 59:
        raise errors.InvalidDataError("RPTCALL index must be <= 59")

    start = call_location(POS_RPTCALL, index)

    return map[start:start+8].strip()

def parse_map_for_memory(map):
    """Returns a list of memories, given a valid memory map"""

    memories = []
    
    for i in range(500):        
        try:
            mem = get_memory(map, i)
        except errors.InvalidMemoryLocation:
            mem = None

        if mem:
            memories.append(mem)

    return memories

def set_freq(map, freq):
    map[POS_FREQ_START] = struct.pack(">i", int((freq * 1000) / 5))[1:]

def set_name(map, _name, enabled=True):
    name = _name.ljust(8)[:8]
    nibbles = []

    def val_of(char):
        if char == " ":
            return 0
        elif char.isdigit():
            return (int(char) & 0x3F) | 0x10
        else:
            return ((ord(char) - ord("A") + 1) & 0x3F) | 0x20

    for i in range(0, len(name), 2):
        c1 = name[i]
        c2 = name[i+1]

        v1 = val_of(c1)
        v2 = val_of(c2)

        nibbles.append((v1 & 0x3F) >> 2)
        nibbles.append(((v1 & 0x03) << 2) | ((v2 & 0x30) >> 4))
        nibbles.append((v2 & 0x0F))

    if enabled:
        nibbles.insert(0, 2)
    else:
        nibbles.insert(0, 0)

    nibbles.append(0)

    val = ""

    for i in range(0, len(nibbles), 2):
        val += struct.pack("B", ((nibbles[i] << 4)| nibbles[i+1]))

    map[POS_NAME_START] = val

def set_duplex(map, duplex):
    mask = 0x3F # ~11000000
    val = struct.unpack("B", map[POS_DUPX])[0] & mask

    if duplex == "-":
        val |= 0x80
    elif duplex == "+":
        val |= 0xC0

    map[POS_DUPX] = val

def set_dup_offset(map, offset):
    val = struct.pack(">H", int(offset * 1000) / 5)

    map[POS_DOFF_START] = val

def set_mode(map, mode):
    mask = 0x8F # ~01110000
    val = struct.unpack("B", map[POS_MODE])[0] & mask

    try:
        val |= ID800_MODES_REV[mode]
    except Exception, e:
        raise errors.InvalidDataError("Unsupported mode `%s'" % mode)

    map[POS_MODE] = val

def set_rtone(map, tone):
    map[POS_RTONE] = struct.pack("B", chirp_common.TONES.index(tone))

def set_ctone(map, tone):
    val = struct.unpack("B", map[POS_CTONE])[0] & 0xC0
    map[POS_CTONE] = struct.pack("B", chirp_common.TONES.index(tone) | val)

def set_dtcs(map, code):
    map[POS_DTCS] = struct.pack("B", chirp_common.DTCS_CODES.index(code))

def set_dtcs_polarity(map, polarity):
    val = struct.unpack("B", map[POS_DTCS_POL])[0] & 0x3F
    pol_values = { "NN" : 0x00,
                   "NR" : 0x40,
                   "RN" : 0x80,
                   "RR" : 0xC0 }

    val |= pol_values[polarity]

    map[POS_DTCS_POL] = val

def set_tone_enabled(map, enc, sql, dtcs):
    mask = 0xFC # ~00000011
    val = struct.unpack("B", map[POS_TENB])[0] & mask

    if dtcs:
        val |= 0x3
    else:
        if enc:
            val |= 0x1
        if sql:
            val |= 0x2

    map[POS_TENB] = val

def set_memory(_map, mem):
    map = get_raw_memory(_map, mem.number)

    set_freq(map, mem.freq)
    set_name(map, mem.name)
    set_duplex(map, mem.duplex)
    set_dup_offset(map, mem.offset)
    set_mode(map, mem.mode)
    set_rtone(map, mem.rtone)
    set_ctone(map, mem.ctone)
    set_dtcs(map, mem.dtcs)
    set_tone_enabled(map,
                     mem.tencEnabled,
                     mem.tsqlEnabled,
                     mem.dtcsEnabled)
    set_dtcs_polarity(map, mem.dtcsPolarity)

    _map[get_mem_offset(mem.number)] = map.get_packed()

    set_used(_map, mem.number, True)

    return _map

def erase_memory(map, number):
    set_used(map, number, False)

    return map

def set_mycall(map, index, call):
    if index > 7:
        raise errors.InvalidDataError("MYCALL index must be <= 7")

    start = call_location(POS_MYCALL, index)
    
    map[start] = call.ljust(8)

    return map

def set_urcall(map, index, call):
    if index > 99:
        raise errors.InvalidDataError("URCALL index must be <= 99")

    start = call_location(POS_URCALL, index)

    map[start] = call.ljust(8)

    return map

def set_rptcall(map, index, call):
    if index > 59:
        raise errors.InvalidDataError("RPTCALL index must be <= 59")

    start = call_location(POS_RPTCALL, index)

    map[start] = call.ljust(8)

    return map

def test_basic():
    v = pack_name("DAN")
    #V = "\x28\xe8\x86\xe4\x80\x00\x00"
    V = "\x29\x21\xb8\x00\x00\x00\x00"

    if v == V:
        print "Pack name: OK"
    else:
        print "Pack name: FAIL"
        print "%s\nnot equal to\n%s" % (util.hexprint(v), util.hexprint(V))

    name = unpack_name(v)

    if name == "DAN":
        print "Unpack name: OK"
    else:
        print "Unpack name: FAIL"

    v = pack_frequency(146.520)
    V = "\x00\x72\x78"

    if v != V:
        print "Pack frequency: FAIL"
        print "%s != %s" % (list(v), list(V))
    else:
        print "Pack frequency: OK"

    freq = unpack_frequency(v)

    if freq != 146.520:
        print "Unpack frequency: FAIL"
        print "%s != %s" % (freq, 146.520)
    else:
        print "Unpack frequency: OK"


if __name__ == "__main__":

    import sys
    import serial
    import os

    test_basic()

    sys.exit(0)

    if len(sys.argv) > 2:
        mm = file(sys.argv[1], "rb")
        map = mm.read()

        #parse_map_for_memory(map)

        pipe = serial.Serial(port=sys.argv[2],
                             baudrate=9600)

        model = "\x27\x88\x02\x00"

        outlog = file("outlog", "wb", 0)

        clone_to_radio(pipe, model, map)
