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

__dff_module_postprocess_version__ = "1.0.0"
from code import InteractiveConsole

from dff.api.module.script import Script 
from dff.api.taskmanager.taskmanager import TaskManager
from dff.api.module.module import Module 
from dff.api.types.libtypes import Variant, Argument, typeId, ConfigManager

from dff.ui.console.completion import LineParser 

class BATCH(Script):
  def __init__(self):
    Script.__init__(self, "batch")
    self.tm = TaskManager()
    self.DEBUG = False
    self.VERBOSITY = 0
    self.lp = LineParser(self.DEBUG, self.VERBOSITY -1)
    self.cm = ConfigManager.Get()
 
  def start(self, args):
    ic = InteractiveConsole()
    path = args["path"].value().path
    print "executing batch script " + path 
    file = open(path) 
    for line in file.xreadlines():
	if line[0] == "#":
	   continue
        elif line[0] == "!":
	  cmds = self.lp.makeCommands(line[1:])
	  for cmd in cmds:
	    exec_type = ["console"]
	    config = self.cm.configByName(cmd[0])
	    args  = config.generate(cmd[1])
	    proc = self.tm.add(cmd[0], args, exec_type)
	    proc.event.wait()
	else:
	   ic.push(line) 
    ic.resetbuffer()
    file.close()
    return

class batch(Module):
  """Process a dff batch file"""
  def __init__(self):
    Module.__init__(self, "batch", BATCH)
    self.conf.addArgument({"name":"path",
			   "description": "Path to a dff batch file",
			   "input" : Argument.Required|Argument.Single|typeId.Path}) 	
    self.tags = "builtins"
