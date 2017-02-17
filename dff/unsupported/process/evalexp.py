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

__dff_module_evalexp_version__ = "1.0.0"

from dff.api.vfs import *
from dff.api.module.module import *
from dff.api.module.script import *
from dff.api.types.libtypes import typeId, Argument, Variant

class EVAL(Script):
  def __init__(self):
    Script.__init__(self, "eval")

  def start(self, args):
    try:
      expr = args["expression"].value()
    except IndexError:
       raise envError("modules evalexp need an expression to evaluate")
    buff = eval(expr)
    self.res["result"] = Variant(buff)
 
class evalexp(Module):
  """Calculate a mathematical expression
Ex: evalexp 2+2"""
  def __init__(self):
    Module.__init__(self, "eval", EVAL)
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.String,
			   "name":"expression",
			   "description":"expression to compute"
			})
    self.tags = "builtins"
