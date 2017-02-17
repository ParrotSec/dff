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

__dff_module_pipe_exec_version__ = "1.0.0"
from subprocess import *

from dff.api.vfs import *
from dff.api.module.script import *
from dff.api.module.module import *
from dff.api.types.libtypes import typeId, Argument

class PIPE_EXEC(Script):
  def __init__(self):
     Script.__init__(self, "pipe_exec")
     self.vfs = vfs.vfs()

  def start(self, args):
     try:
       cmd = args["command"].value()
       node = args["file"].value()
     except IndexError :
	raise envError("pipe_exec need command and file value.")
     file = node.open()
     buff = file.read()
     file.close()
     Popen(cmd,1, shell=1, stdin=PIPE).communicate(buff)

class pipe_exec(Module):
  """open a file and pipe it to an external command
ex: exec_pipe /file.txt less
Take care this use as many ram as the file size, must be used for test purpose only."""
  def __init__(self):
   Module.__init__(self, "pipe_exec", PIPE_EXEC)
   self.conf.addArgument({"name":"file",
			  "description":"File to pipe.",
			  "input": Argument.Required|Argument.Single|typeId.Node})
   self.conf.addArgument({"name":"command",
			  "description":"External command line to execute.",
			  "input": Argument.Required|Argument.Single|typeId.String})
   self.tags = "builtins"	
