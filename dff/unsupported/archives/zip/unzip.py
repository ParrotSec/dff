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

__dff_module_unzip_version__ = "1.0.0"

from dff.api.vfs import vfs
from dff.api.vfs.libvfs import VFS, FdManager, fdinfo, Node, fso
from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.exceptions.libexceptions import vfsError, envError
from dff.api.types.libtypes import vtime, Variant, VMap, Argument, typeId
from dff.api.events.libevents import event

import traceback
import mzipfile

class ZipNode(Node):
  __slots__ = (
    'orig_filename',
    'filename',
    'compress_type',
    'comment',
    'extra',
    'create_system',
    'create_version',
    'extract_version',
    'reserved',
    'flag_bits',
    'volume',
    'internal_attr',
    'external_attr',
    'header_offset',
    'CRC',
    'compress_size',
    '_raw_time',
    )

  def __init__(self, name, size, parent, fsobj, zipfile):
    Node.__init__(self, name, size, parent, fsobj)
    self.zipfile = zipfile
    self.setFile()
    self.reader = fsobj
    self.__disown__()

  def _attributes(self):
    attr = VMap()
    zipattr = self.reader.zipcontent.getinfo(self.zipfile)
    for key in ZipNode.__slots__:
      val = getattr(zipattr, key)
      if key != "date_time":
        attr[key] = Variant(val)
    vt = vtime()
    vt.thisown = False
    vt.year = zipattr.date_time[0]
    vt.month = zipattr.date_time[1]
    vt.day = zipattr.date_time[2]
    vt.hour = zipattr.date_time[3]
    vt.minute = zipattr.date_time[4]
    vt.second = zipattr.date_time[5]
    attr["create"] = Variant(vt) 
    return attr


class UNZIP(fso):
  def __init__(self):
    fso.__init__(self, "unzip")
    self.name = "unzip"
    self.VFS = VFS.Get()
    self.vfs = vfs.vfs()
    self.fdm = FdManager()
    self.origin = None
    self.zipcontent = None
    self.file = None
    self.mapped_files = {}


  def start(self, args):
    origin = args['file'].value()
    self.makeZipTree(origin)

  
  def makeZipTree(self, origin):
    self.origin = origin
    self.file = self.origin.open()
    self.zipcontent = mzipfile.ZipFile(self.file)
    for zipfile in self.zipcontent.namelist():
      idx = zipfile.rfind("/")
      if idx != -1:
        path = zipfile[:idx]
        filename = zipfile[idx+1:]
      else:
        path = ""
        filename = zipfile
      parent = self.vfs.getnode(self.origin.absolute() + "/" + path)
      if parent == None:
        parent = self.makeDirs(path)
      attr = self.zipcontent.getinfo(zipfile)
      node = ZipNode(filename, attr.file_size, parent, self, zipfile)
      node.__disown__()
    e = event()
    e.value = Variant(self.origin)
    self.VFS.notify(e)

  def makeDirs(self, folders):
    sfolders = folders.split("/")
    prev = self.origin
    for folder in sfolders:
      node = self.vfs.getnode(prev.absolute() + "/" + folder)
      if node == None:
        node = Node(folder, 0, prev, self)
        node.setDir()
        node.__disown__()
      prev = node
    return node


  def mappedFile(self, zipfile):
    info = self.zipcontent.getinfo(zipfile)
    buff = ""
    if info.file_size > 0:
      buff = self.zipcontent.read(zipfile)
    return buff


  def nodeToZipFile(self, node):
    abs = node.absolute()
    orig = self.origin.absolute()
    zipfile = abs.replace(orig, "")[1:]
    return zipfile


  def vopen(self, node):
    if not node.size():
      return 0
    zipfile = self.nodeToZipFile(node)
    if zipfile in self.mapped_files.keys():
      buff = self.mapped_files[zipfile]["buff"]
      self.mapped_files[zipfile]["opened"] += 1
    else:
      buff = self.mappedFile(zipfile)
      self.mapped_files[zipfile] = {}
      self.mapped_files[zipfile]["buff"] = buff
      self.mapped_files[zipfile]["opened"] = 1
    fi = fdinfo()
    fi.thisown = False
    fi.node = node
    fi.offset = 0
    fd = self.fdm.push(fi)
    return fd


  def vread(self, fd, buff, size):
    fi = self.fdm.get(fd)
    zipfile = self.nodeToZipFile(fi.node)
    buff = self.mapped_files[zipfile]["buff"]
    if fi.node.size() < fi.offset + size:
      size = fi.node.size() - fi.offset
    if size <= 0:
      return (0, "")
    else:
      res = (size, buff[fi.offset:fi.offset+size])
      fi.offset += size
      return res


  def vseek(self, fd, offset, whence):
    fi = self.fdm.get(fd)
    if whence == 0:
      if offset <= fi.node.size():
        fi.offset = offset
      else:
        formatted_lines = traceback.format_exc().splitlines()
        raise vfsError("[unzip::vseek]" + formatted_lines[-1])
    if whence == 1:
      if fi.offset + offset > fi.node.size():
        fi.offset += offset
      else:
        formatted_lines = traceback.format_exc().splitlines()
        raise vfsError("[unzip::vseek]" + formatted_lines[-1])
    if whence == 2:
      fi.offset = fi.node.size()
    return fi.offset


  def vclose(self, fd):
    try:
      fi = self.fdm.get(fd)
      zipfile = self.nodeToZipFile(fi.node)
      self.fdm.remove(fd)
      if self.mapped_files[zipfile]["opened"] == 1:
        del self.mapped_files[zipfile]
      else:
        self.mapped_files[zipfile]["opened"] -= 1
      return 0
    except:
      return 0


  def vtell(self, fd):
    fi = self.fdm.get(fd)
    return fi.offset


  def status(self):
    return len(self.mapped_files)


class unzip(Module):
  """Decompress zip file and create their content in virtual memory through module SHM.
This version of unzip store all data in RAM so don't decompress huge file."""
  def __init__(self):
    Module.__init__(self, "unzip", UNZIP)
    self.conf.addArgument({"name": "file",
                           "input": Argument.Required|Argument.Single|typeId.Node,
                           "description": "zip file to decompress"
                           })
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["Zip"]})
    self.tags = "Archives"
    self.icon = ":zip"
