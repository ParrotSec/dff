# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
# 
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
#  Christophe Malinge <cma@digital-forensic.org>

__dff_module_metaexif_version__ = "1.0.0"

from time import strptime
from PIL import Image
from PIL.ExifTags import TAGS

from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.module.manager import ModuleProcessusHandler
from dff.api.types.libtypes import Variant, VMap, VList, Argument, typeId, vtime
from dff.api.vfs.libvfs import AttributesHandler, VFS

class EXIFHandler(AttributesHandler, ModuleProcessusHandler):
  dateTimeTags = [0x0132, 0x9003, 0x9004]
  def __init__(self):
    AttributesHandler.__init__(self, "exif")
    ModuleProcessusHandler.__init__(self, "metaexif")
    self.exifnodes = []
    self.vfs = VFS.Get()
    self.__disown__()
 
  def update(self, processus):
     pass
 
  def nodes(self, root):
     lnodes = []
     rootAbsolute = root.absolute()
     for node in self.exifnodes:
        node = self.vfs.getNodeFromPointer(node)
	if node.absolute().find(rootAbsolute) == 0:
	  lnodes.append(node)
     return lnodes

  def setAttributes(self, node):
     self.exifnodes.append(long(node.this)) 

  def haveExif(self, node):
    vfile = node.open()
    img = Image.open(vfile) 
    info = img._getexif()
    vfile.close()
    if info == None:
	return False
    if len(info):
      return True
    return False

  def attributes(self, node):
    attr = VMap()
    vfile = node.open()
    img = Image.open(vfile) 
    info = img._getexif()
    vfile.close()
    for tag, values in info.items():
      if tag in self.dateTimeTags:
       try:
	decoded = str(TAGS.get(tag, tag))
 	try:
	  dt = strptime(values, "%Y:%m:%d %H:%M:%S") 
        except ValueError:
	  try:
	    dt = strptime(values[:-6], "%Y-%m-%dT%H:%M:%S")
	  except ValueError:
	    dt = strptime(values.rstrip(' '),  "%a %b %d %H:%M:%S")
	vt = vtime(dt.tm_year, dt.tm_mon, dt.tm_mday, dt.tm_hour, dt.tm_min, dt.tm_sec, 0)
        vt.thisown = False
	attr[decoded] = Variant(vt) 	
       except Exception as e:
	attr[decoded] = Variant(str(values))
      else:	
        decoded = str(TAGS.get(tag, tag))
        if isinstance(values, tuple):
	  vl = VList()
	  for value in values:
	     vl.push_back(Variant(value))
          attr[decoded] = vl
        else:
          attr[decoded] = Variant(values)
    return attr

class MetaEXIF(Script):
  def __init__(self):
   Script.__init__(self, "metaexif")
   self.handler = EXIFHandler() 

  def start(self, args):
    try:
      node = args['file'].value()
      attr = self.handler.haveExif(node)
      if attr == True:
        self.stateinfo = "Registering node: " + str(node.name())
        self.handler.setAttributes(node)
        node.registerAttributes(self.handler)
    except KeyError:
      pass

class metaexif(Module): 
  """This modules generate exif metadata in node attributes"""
  def __init__(self):
    Module.__init__(self, "metaexif", MetaEXIF)
    self.conf.addArgument({"name": "file",
                           "description": "file for extracting metadata",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["jpeg", "TIFF"]})
    self.flags = ["single"]
    self.tags = "Metadata"
