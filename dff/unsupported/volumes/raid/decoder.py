# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.
#  
# See http://www.digital-forensic.org for more information about this
# project. Please do not directly contact any of the maintainers of
# DFF for assistance; the project provides a web site, mailing lists
# and IRC channels for your use.
# 
# Author(s):
#  Jeremy Mounier <jmo@digital-forensic.org>
# 

import binascii
import struct

STRING_T = 0
UINT8_T = 1
INT8_T = 2
UINT16_T = 3
INT16_T = 4
UINT32_T = 5
INT32_T = 6
UINT64_T = 7
INT64_T = 8
VOID_T = 9

TEMP_OFFSET = 0
TEMP_SIZE = 1
TEMP_TYPE = 2

class decoder():
    def __init__(self, vfile, offset, template):
        self.vfile = vfile
        self.offset = offset
        self.temp = template
        self.decoded = False
        self.decode()

    def template(self):
        return sorted(self.temp.iteritems(), key=lambda (k,v): (v,k))

    def readTemplate(self):
        buff = ""
        for field, data in self.template():
            self.vfile.seek(self.offset + data[TEMP_OFFSET])
            buff += self.vfile.read(data[TEMP_SIZE])
        return buff

    def pattern(self):
        pattern = "<"
        for field, data in self.template():
            if data[TEMP_TYPE] == INT8_T:
                pattern += "b"
            elif data[TEMP_TYPE] == UINT8_T:
                pattern += "B"
            elif data[TEMP_TYPE] == INT16_T:
                pattern += "h"
            elif data[TEMP_TYPE] == UINT16_T:
                pattern += "H"
            elif data[TEMP_TYPE] == INT32_T:
                pattern += "i"
            elif data[TEMP_TYPE] == UINT32_T:
                pattern += "I"
            elif data[TEMP_TYPE] == INT64_T:
                pattern += "q"
            elif data[TEMP_TYPE] == UINT64_T:
                pattern += "Q"
            elif data[TEMP_TYPE] == STRING_T:
                pattern += str(data[TEMP_SIZE]) + "s"
            elif data[TEMP_TYPE] == VOID_T:
                pattern += str(data[TEMP_SIZE]) + "P"
        return pattern

    def decode(self):
        if not self.decoded:
            buff = self.readTemplate()

            if self.templateSize() == len(buff):
                res = struct.unpack(self.pattern(), buff)
                cp = 0
                self.filds = {}
                for key, values in self.template():
                    setattr(self, key, res[cp])
                    cp += 1
                self.decoded = True

    def dump(self):
        for field, data in self.template():
            print field, " : ", getattr(self, field)

    # Unused : information purpose
    def templateSize(self):
        size = 0
        for field, data in self.template():
            size += data[TEMP_SIZE]
        return size
