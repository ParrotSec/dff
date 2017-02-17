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
#  Frederic Baguelin <fba@arxsys.fr>
#

__dff_module_merge_version__ = "1.0.0"
import time

from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.types.libtypes import Variant, VList, VMap, Argument, Parameter, typeId
from dff.api.search.libsearch import Search

class FCHUNKS(Script):
    def __init__(self):
       Script.__init__(self, "fchunks")

    def start(self, args):
       self.sample = args['sample'].value()
       self.dump = args['dump'].value()
       if args.has_key("chunk_size"):
          self.csize = args["chunk_size"].value()
       else:
          self.csize = 512
       self.search = Search()
       self.search.setPatternSyntax(Search.Fixed)
       self.search.setCaseSensitivity(Search.CaseSensitive)
       fdump = self.dump.open()
       fsample = self.sample.open()
       stime = time.time()
       buff = fdump.read(10*1024*1024)
       while len(buff) > 0:
           fsample.seek(0)
           buff2 = fsample.read(self.csize)
           while len(buff2) > 0:
               self.search.setPattern(buff2)
               idx = self.search.find(buff)
               if idx != -1:
                   print hex(fsample.tell()-len(buff2)), "--", hex(fsample.tell()), "   matched @ ", hex(fdump.tell()-len(buff)+idx)
               buff2 = fsample.read(self.csize)               
           buff = fdump.read(10*1024*1024)
           print fdump.tell(), "/", self.dump.size()
       print "run in: ", time.time() - stime
       fsample.close()
       fdump.close()


class fchunks(Module):
  """This module is designed to concat 2 files."""
  def __init__(self):
    Module.__init__(self, "fchunks", FCHUNKS)
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node,
                           "name": "sample",
                           "description": "each fragment of this file will be search in the reference dump"
                           })
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node,
                           "name": "dump",
                           "description": "the dump where to look for the fragments"
                           })
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.UInt32,
                           "name": "chunk_size",
                           "description": "minimum size of chunk to look for (default is 512)",
                           "parameters": {"type": Parameter.Editable,
                                              "predefined": [512, 1024, 2048, 4096, 8192]}
                           })
    self.tags = "Node"
