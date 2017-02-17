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

__dff_module_unxor_version__ = "1.0.0"

from dff.api.module import *
from dff.api.exceptions.libexceptions import *
from dff.api.types.libtypes import Argument, typeId, Variant

from dff.modules.shm.touch import *

class UNXOR(Script):
  def __init__(self):
    Script.__init__(self, "unxor")
    self.vfs = vfs.vfs()
    self.touch = TOUCH().touch

  def start(self, args):
    try:
      node = args['file'].value()
      key = args['key'].value()
      res = self.unxor(node, key)
      self.res["result"] = Variant(res)
    except:
      pass

  def unxor(self, node, key):
    dfilename = node.absolute() +  "/decrypted"
    dfile = self.touch(dfilename).open()
    file = node.open()
    decrypt = ""
    ki = 0
    try:
      buff = file.read(4096)
    except vfsError, e:
      return "error"
    while len(buff) > 0:
      for x in range(len(buff)):
        dfile.write(chr(ord(buff[x]) ^ ord(key[ki])))
        ki = (ki + 1) % len(key)
      try:
        buff = file.read(4096)
      except vfsError, e:
        file.close()
        dfile.close()
      return dfilename + " decrypted"
    file.close()
    dfile.close()
    return dfilename + " decrypted" 

class unxor(Module):
  """Decrypt a XORed file
ex: unxor /myfile key"""
  def __init__(self):
    Module.__init__(self, "unxor", UNXOR)
    self.conf.addArgument({"name": "file",
                           "description": "xored file",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "key",
                           "description": "key to unxor",
                           "input": Argument.Required|Argument.Single|typeId.String})
    self.tags = "Crypto"
    self.icon = ":unlock"
