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

__dff_module_volatility_version__ = "1.0.0"

import sys
import os
import forensics.registry as MemoryRegistry

from vmodules import *

from dff.api.vfs import *
from dff.api.module.module import *
from dff.api.module.script import *
from dff.api.types.libtypes import typeId, Argument

from dfwrapper import *
#XXX fix dump options

class Volatility(mfso):
  def __init__(self):
    mfso.__init__(self, "volatility")
    self.__disown__()
    self.name = "volatility"
    self.vfs = vfs.vfs()

  def start(self, args):
    self.node = args["file"].value()
    self.meta = False
    self.dump = False
    self.connections = False
    self.openfiles = False
    if args.has_key("meta"):
      self.meta = True
    if args.has_key("dump"):
      self.dump = True
    if args.has_key("connections"):
      self.connections = True
    if args.has_key("openfiles"):
      self.openfiles = True
    self.root = Node("volatility")
    self.root.__disown__()
    self.op = op(self.node)
    (self.addr_space, self.symtab, self.types) = load_and_identify_image(self.op, self.op)
    self.proclist = self.pslist()
       

    for proc in self.proclist:
     if self.meta:
       proc.getMeta()
     if self.dump:
       e = proc.dump()
       if e:         
         self.res["error"] = Variant(e)
     if self.openfiles:
       proc.getOpenFiles() 
     if self.connections:
       proc.getConnections() 
     #proc.file.close()
    self.registerTree(self.node, self.root)
 
  def pslist(self):	
    self.all_tasks = process_list(self.addr_space,self.types,self.symtab)
    lproc = []
    for task in self.all_tasks:
      if not self.addr_space.is_valid_address(task):
          continue
      lproc.append(processus(self, task, self.op.filename, self.addr_space, self.types, self.symtab))
    return lproc


class volatility(Module):
  """Analyse a windows-xp ram dump"""
  def __init__(self):
   Module.__init__(self, "windows-XP", Volatility)
   self.conf.addArgument({"name": "file",
                          "description": "Dump to analyse", 
                          "input": Argument.Required|Argument.Single|typeId.Node})
   self.conf.addArgument({"name": "meta",
                          "description": "Generate meta-data for each processus", 
                          "input": Argument.Empty})
   self.conf.addArgument({"name": "dump",
                          "description": "Dump processus data content",
                          "input": Argument.Empty})
   self.conf.addArgument({"name": "openfiles",
                          "description": "List opened files per processus",
                          "input": Argument.Empty})
   self.conf.addArgument({"name": "connections",
                          "description": "List opened connection per processus",
                          "input": Argument.Empty})
   self.conf.addConstant({"name": "extension-type",
			  "type" : typeId.String,
			  "description" : "Compatible extension",
			  "values" : ["vmem"]})
   self.tags = "RAM"
   self.icon = ":dev_ram.png"
