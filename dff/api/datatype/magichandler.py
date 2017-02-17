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
#  Solal J. <sja@digital-forensic.org>
#
import os, sys

if hasattr(sys, "frozen"):
   from dff.api.magic import magic
else:
    try:
       import magic
    except:
       from dff.api.magic import magic

from dff.api.exceptions.libexceptions import vfsError 
from dff.api.types.libtypes import Variant
from dff.api.datatype.libdatatype import DataTypeHandler, DataTypeManager

class MagicHandler(DataTypeHandler):
  def __init__(self, name):
     DataTypeHandler.__init__(self, name)
     self.__disown__()
     self.mgc_path = None
     if os.name == "nt":
       if hasattr(sys, "frozen"):
          self.mgc_path = os.path.abspath(os.path.join(os.path.dirname(sys.executable), "resources/magic.mgc"))
       else:
          self.mgc_path = os.path.join(sys.path[0], "dff/api/magic/magic.mgc")

  def type(self, node):
    if node.size() > 0:
      mime = magic.open(self.magic_type())
      if self.mgc_path:
        mime.load(self.mgc_path)
      else:
        mime.load()
      filemime = None 
      try:
        f = node.open()
      except :
	return self.empty(node)
      try:	
        buff = f.read(0x2000)
        filemime = mime.buffer(buff)
      finally:
        f.close()
        mime.close()	
      if filemime: 
        return filemime
      else:
	return "data"
    else:
	return self.empty(node)

class Magic(MagicHandler):
    def __init__(self):
       MagicHandler.__init__(self, "magic")

    def magic_type(self):
       return magic.MAGIC_NONE

    def empty(self, node):
       if node.hasChildren():
	 return "directory"
       else:
	 return "empty"

class MagicMime(MagicHandler):
   def __init__(self):
      MagicHandler.__init__(self, "magic mime")
      
   def magic_type(self):
      return magic.MAGIC_MIME

   def empty(self, node):
      if node.hasChildren():
        return "application/x-directory; charset=binary"
      else:
        return "application/x-empty; charset=binary"

magicMimeHandler = MagicMime()
magicHandler = Magic()
