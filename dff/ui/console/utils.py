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
#  Frederic Baguelin <fba@digital-forensic.org>
#
import sys, os, string, struct, re

if os.name == "posix":
  import tty, termios, fcntl
elif os.name == "nt":
  import msvcrt
  from ctypes import windll, create_string_buffer

from dff.api.types.libtypes import typeId

class ConsoleAttributes():
    class __posix():
        def __init__(self):
            pass

        def terminalSize(self):
            width = 80
            s = struct.pack('HHHH', 0, 0, 0, 0)
            s = fcntl.ioctl(1, termios.TIOCGWINSZ, s)
            twidth = struct.unpack('HHHH', s)[1]
            if twidth > 0:
                width = twidth
            return width

    class __nt():
        def __init__(self):
            pass

        def terminalSize(self):
            h = windll.kernel32.GetStdHandle(-12)
            csbi = create_string_buffer(22)
            res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
            if res:
                (bufx, bufy, curx, cury, wattr, left, top, right, bottom, maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
                sizex = right - left + 1
            else:
                sizex = 80
            return sizex


    def __init__(self):
        if os.name == "posix":
            ConsoleAttributes.__instance = ConsoleAttributes.__posix()
        elif os.name == "nt":
            ConsoleAttributes.__instance = ConsoleAttributes.__nt()


    def __setattr__(self, attr, value):
        setattr(self.__instance, attr, value)
  

    def __getattr__(self, attr):
        return getattr(self.__instance, attr)


class VariantTreePrinter():
    def __init__(self):
        self.consoleAttr = ConsoleAttributes()
        self.maxitems = -1
        self.maxdepth = -1
        self.currentdepth = 0


    def setMaxItemListToExpand(self, maxitems=-1):
        self.maxitems = maxitems


    def setMaxDepth(self, maxdepth=-1):
        self.maxdepth = maxdepth
        self.currentdepth = 0


    def fillMap(self, spacer, vmap, res=""):
        self.termsize = self.consoleAttr.terminalSize()
        for key in vmap.iterkeys():
            vval = vmap[key]
            res += "\n" + ("\t" * spacer) + str(key)
            if vval.type() == typeId.Map:
                if (self.maxdepth == -1 or self.currentdepth < self.maxdepth):
                    vvmap = vval.value()
                    self.currentdepth += 1
                    res += self.fillMap(spacer+1, vvmap)
                    self.currentdepth -= 1
            elif vval.type() == typeId.List:
                vlist = vval.value()
                size = len(vlist)
                res += ": total items (" + str(size) + ")\n"
                res += self.fillList(spacer+1, vlist)
            else:
                if vval.type() == typeId.VTime:
                    vtime = vval.value()
                    res += ": " + str(vtime.get_time())
                elif vval.type() in [typeId.Char, typeId.Int16, typeId.UInt16, typeId.Int32, typeId.UInt32, typeId.Int64, typeId.UInt64]:                
                    res += ": " + str(vval.toString() + " - " + vval.toHexString())
                elif vval.type() == typeId.Node:
                    res += ": " + str(vval.value().absolute())
                elif vval.type() in [typeId.Path, typeId.String, typeId.Bool]:
                    res += ": " + str(vval.toString())
        return res


    def fillList(self, spacer, vlist, res=""):
        x = self.consoleAttr.terminalSize()
        res += "\n" + (spacer * "\t")
        count = len(vlist) - 1
        crop = False
        if self.maxitems != -1:
            cropbegidx = self.maxitems / 2
            cropendidx = count - self.maxitems / 2
        else:
            cropbegidx = -1
            cropendidx = -1
        idx = 0
        xpos = len("\t" * spacer)
        for vval in vlist:
            if vval.type() == typeId.Map:
                vmap = vval.value()
                self.currentdepth -= 1
                res += self.fillMap(spacer, vmap)
                self.currentdepth += 1
            elif vval.type() == typeId.List:
                vvlist = vval.value()
                res += self.fillList(spacer, vvlist)
            else:
                vstr = ""
                if not crop:
                    if vval.type == typeId.VTime:
                        vtime = vval.value()
                        vstr = str(vtime.get_time())
                    elif vval.type() == typeId.Node:
                        vstr = str(vval.value().absolute())
                    elif vval.type() in [typeId.Path, typeId.String]:
                        vstr = str(vval.toString())
                    else:
                        vstr = str(vval.toString() + " - " + vval.toHexString())
                    if count:
                        vstr += ", "
                    xpos += len(vstr)
                    if xpos > x - 20:
                        res += "\n" + (spacer * "\t") + vstr
                        xpos = len(spacer * "\t") + len(vstr)
                    else:
                        res += vstr
            if cropbegidx != -1 and idx == cropbegidx:
                crop = True
                res += "\n\n" + (spacer * "\t") + (" " * ((x - 20 - len(spacer * "\t")) / 2)) + "[...]" + "\n\n" + (spacer * "\t")
                xpos = len(spacer * "\t")
            if cropendidx != -1 and idx == cropendidx:
                crop = False
            count -= 1
            idx += 1
        return res
