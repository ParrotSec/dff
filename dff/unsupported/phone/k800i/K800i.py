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
#  Solal Jacob <sja@digital-forensic.org>
#

__dff_module_K800i_version__ = "1.0.0"

from struct import unpack

from dff.api.vfs import *
from dff.api.module.module import *
from dff.api.types.libtypes import Variant, VMap, Argument, typeId, Parameter
from dff.api.vfs.libvfs import *

from dff.modules.spare import SpareNode

class SEPartition():
  def __init__(self, buff):
    self.name = unpack('28s', buff[0:28])[0]
    self.name = self.name[:self.name.find('\x00')]
    self.val1 = unpack('<H', buff[28:30])[0]
    self.val2 = unpack('<H', buff[30:32])[0]
    self.blocksize = unpack('<H', buff[32:34])[0]
    self.start = unpack('<I', buff[34:38])[0] / 0x10000
    self.val4 = unpack('<H', buff[38:40])[0] 
    self.size = unpack('<H', buff[40:42])[0] 

  def __str__(self):
    buff = ""
    buff += "partition name: " + str(self.name) + "\n"
    buff += "fat partition start: " + hex(self.start) + "\n"
    buff += "blocksize: " + str(self.blocksize) + "\n"
    buff += "val1: " + hex(self.val1) + "\n"
    buff += "val2: " + hex(self.val2) + "\n"
    buff += "val4: " + hex(self.val4) + "\n"
    buff += "size in blocks: " + hex(self.size) + "\n"

    return buff

class SEPartitionBlock():
   def __init__(self, virtual, blockoff, blockSize):
    file = virtual.open()
    file.seek(blockoff * blockSize)     
    buff = file.read(blockSize)
    file.close()         
    self.partTable = []

    for i in range(0, len(buff)/48):
      part = buff[i*48:(i*48) + 48]
      if part[0] == "/":
        self.partTable.append(SEPartition(part))
   
   def __str__(self):
     count = 0
     buff = ""
     for table in self.partTable:
        buff += "partition " + str(count) + "\n"
	buff += str(table) + "\n"
        count += 1
     return buff

class Table():
  def __init__(self, offset):
     self.blockList = [] 
     self.blockoffset = offset

  def fill(self, buff):
     self.header = unpack('<II', buff[0:8])
     self.read = unpack('<I', buff[8:12])[0]
     self.read = self.read & 0x00ffffff
     self.mapId = unpack('<I', buff[12:16])[0]
     self.write = unpack('<H', buff[16:18])[0] 
     buff = buff[24:]
     self.blockList = [unpack('<960I', buff[:960*4])]

  def __str__(self):
     listedBlock = 0
     buff = "Header: "  + str(self.header)  + "\n"
     buff += "list len " +  str(len(self.blockList)) + "\n"
     buff += "listed block " + str(listedBlock)	+ "\n"
     return buff	


class TablesList():
  def __init__(self, fullfs, blockSize, nId):
    self.header = "\xDF\xDA\x17\x00\xD7\x98\xD3\x0A"
    self.list = []
    file = fullfs.open()
    tableListOf = file.find(self.header)
    file.seek(tableListOf + 16)
    buff = file.read(blockSize - 16)
    for x in range(0, nId):
      write = unpack('<H', buff[0:2])[0]
      read = unpack('<I', buff[8:12])[0]
      if read == 0x00:
	break	
      self.list.append((write, read)) 
      buff = buff[16:]	
    file.close()  

class Tables():
  def __init__(self, fullfs, blockSize):
    self.header =  '\xDF\xDA\x19\x00\xD7\x98\xD3\x0A'
    self.fullfs = fullfs
    self.blockSize = blockSize
    file = fullfs.open()

    self.tablesIdMap = {}
    self.tablesIdWriteMap = {}
    tableOffset = file.search(self.header, 8, "")
    for offset in tableOffset:
       file.seek(offset)
       buff = file.read(blockSize)
       if len(buff):
         t = Table(offset/(blockSize))
         t.fill(buff)
         try :
	    self.tablesIdMap[t.mapId] += [t]
         except KeyError:
            self.tablesIdMap[t.mapId] = [t] 
         try:
            self.tablesIdWriteMap[t.mapId][t.write] =t 
         except KeyError:
            wlist = {}
	    wlist[t.write] = t
            self.tablesIdWriteMap[t.mapId] = wlist
    file.close()
    self.tablesList = TablesList(fullfs, blockSize, len(self.tablesIdMap)) 
    self.getMap()

  def tableDiff(self):
    self.map = {}
    for id in self.tablesIdMap:
	tablesList =  self.tablesIdMap[id]
        same = []
        for x in range(0, len(tablesList) - 1):
          if tablesList[x].blockList == tablesList[x + 1].blockList:
             same += [tablesList[x]] 
          else:
	     pass
        for table in same:
            tablesList.remove(table)

  def getMap(self):
     self.map = {}
     for id in range(0, len(self.tablesList.list)):
       write = self.tablesList.list[id][0]
       self.map[id] = self.tablesIdWriteMap[id][write]

class SESegment():
   def __init__(self, buff):
      self.start = unpack('<I', buff[0:4])[0] 
      self.end = unpack('<I', buff[8:12])[0] 
      self.size = self.end - self.start + 1
      self.erasesize = unpack('<I', buff[16:20])[0] 
      self.blocksize = unpack('<H', buff[20:22])[0]
      self.val7 = unpack('<I', buff[22:26])[0] 
      self.type = unpack('<H', buff[26:28])[0] 

   def __str__(self):
      buff = "" 
      buff += "segment start: " + hex(self.start) + "\n"
      buff += "segment end: " + hex(self.end) + "\n"
      buff += "erase block size: " + hex(self.erasesize) + "\n"
      buff += "block size: " + hex(self.blocksize) + "\n"
      buff += "val 7: " + hex(self.val7) + "\n"
      buff += "type: " + hex(self.type) + "\n"
      return buff


class SEBootBlock():
   def __init__(self, nor, pageSize):
     file = nor.open()
     self.norfsoffset = file.search('\x03\x00\x1a\x00\x00\x00\x00\x00', 8, '')[-1]
     file.seek(self.norfsoffset)
     buff = file.read(pageSize)
     file.close()
     self.header = unpack('<I', buff[0:4])[0] 
     self.val0 = unpack('<I', buff[4:8])[0]
     self.partitionblock = unpack('<I', buff[8:12])[0] - 1 
     self.segment = []
     buff = buff[16:]
     for i in range(0, len(buff)/ 32):
       seg = unpack('<I', buff[i*32 :(i*32)+4])[0]     
       if seg != 0 and seg != 0xffffffff:
	 self.segment.append(SESegment(buff[i*32: (i*32)+32])) 
     if len(self.segment):
       self.blockSize = self.segment[0].blocksize

   def __str__(self):
     buff = ""
     buff += "boot header: " + hex(self.header) + "\n"
     buff += "se partition start:" + hex(self.partitionblock) + "\n"
     buff += "val 0:" + hex(self.val0) + "\n"
     count = 0	
     for seg in self.segment:
        buff += "segment " + str(count) + ": \n"
        buff += str(seg)
	count += 1
     return buff

class Firmware(Node):
   def __init__(self, mfso, parent, nor, name, noroffset):
     self.ssize = noroffset 
     Node.__init__(self, name, self.ssize, parent, mfso)
     self.__disown__()
     self.nor = nor 
     self.noroffset = noroffset
     self.setFile()

   def fileMapping(self, fm):
     fm.push(0, self.noroffset, self.nor, 0) 
      
class NorFs(Node):
   def __init__(self, mfso, parent, nor, name, boot):
     self.ssize = boot.segment[0].size
     self.noroffset = boot.norfsoffset
     Node.__init__(self, name, self.ssize, parent, mfso)
     self.__disown__()
     self.nor = nor 
     self.setFile()

   def fileMapping(self, fm):
     fm.push(0, self.ssize, self.nor, self.noroffset) 
     
class GDFS(Node):
  def __init__(self, mfso, parent, nor, name, boot):
     self.ssize =  nor.size() - (boot.norfsoffset + boot.segment[0].size)
     self.boot = boot
     Node.__init__(self, name, self.ssize, parent, mfso)
     self.__disown__()
     self.nor = nor 
     self.noroffset = self.boot.norfsoffset
     self.setFile()

  def fileMapping(self, fm):
     fm.push(0, self.ssize, self.nor, self.noroffset + self.boot.segment[0].size) 

class FullFs(Node):
   def __init__(self, mfso, parent, norfs, nandfs, name, boot):
     self.ssize = norfs.size() + (nandfs.size() + (448*8*512))  #XXX fix partition shift  
     #self.ssize = norfs.size() + nandfs.size()   #XXX fix partition shift  
     self.boot = boot
     Node.__init__(self, name, self.ssize, parent, mfso)
     self.__disown__()
     self.norfs = norfs 
     self.nandfs = nandfs
     self.setFile()

   def fileMapping(self, fm):
     fm.push(0, self.norfs.size(), self.norfs, 0)
     fm.push(self.norfs.size(), (448*512*8), None, 0) 
     fm.push(self.norfs.size() + (448*512*8), self.nandfs.size(), self.nandfs, 0) 
     #fm.push(self.norfs.size() , self.nandfs.size(), self.nandfs, 0) 

   def _attributes(self):
      attr = VMap()
      for i in xrange(0, 2):
        vmap = VMap()
        name = ["segment 0 (norfs)", "segment 1 (nandfs)"]        
        vmap["start offset"] = Variant(self.boot.segment[i].start)
        vmap["end offset"] = Variant(self.boot.segment[i].end)
        vmap["size"] = Variant(self.boot.segment[i].size)
        vmap["erse block size"] = Variant(self.boot.segment[i].erasesize)
        vmap["block size"] = Variant(self.boot.segment[i].blocksize)
        attr[name[i]] = Variant(vmap)
      return attr

class VirtualMap(Node):
   def __init__(self, mfso, parent, fullfs, tables, name, blockSize):
     self.ssize = fullfs.size() 
     self.nblocks = fullfs.size() / blockSize
     Node.__init__(self, name, self.ssize, parent, mfso)
     self.__disown__()
     self.fullfs = fullfs
     self.tables = tables
     self.blockSize = blockSize
     self.mapTable()
     self.setFile()

   def mapTable(self): 
    self.map = {}
    self.imap = {}
    self.aalloc = 0
    for t in self.tables.map:
      table = self.tables.map[t]
      for block in xrange(0, len(table.blockList[0])):
        mask = (table.blockList[0][block] >> 16)
        mask = mask << 16
        virtblock = (table.blockList[0][block] ^ mask) - 1
        realblock = (table.mapId *960 + block)
        if virtblock <= self.nblocks:
          try :
            omap = self.imap[virtblock][0]
            oblock = self.imap[virtblock][1]
            self.aalloc += 1
          except KeyError:
              self.map[virtblock] = realblock 
              self.imap[virtblock] = (table, block)

   def fileMapping(self, fm):
     for block in xrange(0, self.nblocks):
       try :
         realblock = self.map[block]
       except KeyError:
         realblock = block
       if realblock >= self.nblocks:
         fm.push(block * self.blockSize, self.blockSize)
       else:
         fm.push(block * self.blockSize, self.blockSize, self.fullfs, realblock * self.blockSize) 
      
   def _attributes(self):
      attr = VMap()
      vmap = VMap()
      for t in self.tables.map:
        vmap[hex(t)] = Variant(hex(self.tables.map[t].write))
      attr["tables"] = Variant(vmap)
      attr["reallocated blocks"] = Variant(self.aalloc)
      return attr	

class Partition(Node):
   def __init__(self, mfso, parent, virtual, partTable, blockSize):
     self.ssize = partTable.size * blockSize 
     Node.__init__(self, "part_" + str(partTable.name[1:]), self.ssize, parent, mfso)
     self.__disown__()
     self.virtual = virtual 
     self.blockSize = blockSize
     self.partTable = partTable
     self.setFile()

   def fileMapping(self, fm):
     startOff = (self.partTable.start - 1) * self.blockSize
     if (startOff + self.ssize) > self.virtual.size():
       leak = (startOff + self.ssize) - self.virtual.size()
       leakOff = self.virtual.size() - startOff                
       fm.push(0, leakOff, self.virtual, startOff) 
       fm.push(leakOff, leak)
     else:
       fm.push(0, self.ssize, self.virtual, startOff) 
      
   def _attributes(self):
      attr = VMap()
      attr["partition start"] = Variant(self.partTable.start)
      attr["blocksize"] = Variant(self.partTable.blocksize)
      attr["size in block"] = Variant(self.partTable.size)
      return attr

class K800I(mfso):
    def __init__(self):
       mfso.__init__(self, "K800i")
       self.name = "K800i"
       self.__disown__()

    def start(self, args):
      try:
        self.nor = args['nor'].value()
        self.nand = args['nand'].value()
      except IndexError:
        return 
      try: 
        self.spareSize = args["spare-size"].value()
      except IndexError:
	self.spareSize = 16
      try:
        self.pageSize = args["page-size"].value()
      except IndexError:
	self.pageSize = 512
      self.k800n = Node("k800")
      self.k800n.__disown__()
      self.boot = SEBootBlock(self.nor, self.pageSize) 
      self.blockSize = self.boot.blockSize
      self.nandClean = SpareNode(self, self.nand, "nandfs", self.pageSize, self.spareSize, self.k800n)
      self.norFs = NorFs(self, self.k800n,  self.nor, "norfs", self.boot)
      self.fullFs = FullFs(self, self.k800n, self.norFs, self.nandClean, "fullfs", self.boot) 
      self.gdfs = GDFS(self, self.k800n, self.nor, "gdfs", self.boot)
      self.firmware = Firmware(self, self.k800n,  self.nor, "firmware", self.boot.norfsoffset)
      self.tables = Tables(self.fullFs, self.blockSize)
      self.virtual = VirtualMap(self, self.k800n, self.fullFs, self.tables, "virtual", self.blockSize)

      self.separt =  SEPartitionBlock(self.virtual, self.boot.partitionblock, self.blockSize)
      self.createPart()
      self.registerTree(self.nand, self.k800n)

    def createPart(self):
      for part in self.separt.partTable:
       if part.start > 0:
         p = Partition(self, self.k800n, self.virtual, part, self.blockSize)

class K800i(Module):
  """This modules permit to browse the content of a K800i phones."""
  def __init__(self):
    Module.__init__(self, "k800i", K800I)
    self.conf.addArgument({"name": "nor",
                           "description": "K800i nor dump",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "nand",
                           "description": "K800i nand dump",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "spare-size",
                           "description": "size of nand spare",
                           "input": Argument.Optional|Argument.Single|typeId.UInt32,
                           "parameters": {"type": Parameter.Editable,
                                          "predefined": [16, 8, 32, 64]}
                           })
    self.conf.addArgument({"name": "page-size",
                           "description": "size of nand page",
                           "input": Argument.Optional|Argument.Single|typeId.UInt32,
                           "parameters": {"type": Parameter.Editable,
                                          "predefined": [512, 256, 1024, 2048, 4096]}
                           })
    self.tags = "Mobile"
