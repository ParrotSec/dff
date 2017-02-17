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

__dff_module_gen_nodes_version__ = "1.0.0"

from struct import unpack

from dff.api.types.libtypes import Variant, VMap, Parameter, Argument, typeId
from dff.api.vfs.libvfs import AttributesHandler, mfso, Node
from dff.api.vfs.vfs import vfs
from dff.api.module.module import Module 

class HugeNode(Node):
    def __init__(self, mfso, name, size):
        Node.__init__(self, name, size, None, mfso)
        self.__disown__()

        
    def fileMapping(self, fm):
        fm.push(0, self.size(), None, 0)
      

    def _attributes(self):
        vm = VMap()
        return vm


class HugeNodes(mfso):
    def __init__(self):
        mfso.__init__(self, "HugeNodes")
        self.name = "HugeNodes"
        self.__disown__()


    def start(self, args):
        self.parent = args["parent"].value()
        hn = HugeNode(self, "huge node " + str(2**64-1), 2**64-1)
        hn.thisown = False
        hn.__disown__()
        self.registerTree(self.parent, hn)


class huge_node(Module): 
  """This modules permit to test the framework by generating a large amount of nodes."""
  def __init__(self):
    Module.__init__(self, "huge_node", HugeNodes)
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Node, 
	                   "name": "parent", 
	                   "description": "files or folders will be added as child(ren) of this node or as the root node by default",
                           "parameters": {"type": Parameter.Editable,
                                          "predefined": [vfs().getnode("/")]}
                          })
    self.tags = "Node"
