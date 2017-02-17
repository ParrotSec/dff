/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include "pyrun.swg"

%module PARTITION
%include "std_list.i"
%include "std_map.i"
%include "windows.i"


%{
#include "node.hpp"
#include "vlink.hpp"
#include "variant.hpp"
#include "vtime.hpp"
#include "export.hpp"
#include "partition.hpp"
#include "rootnode.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "partition.hpp"


%pythoncode
%{

__dff_module_partition_version__ = "1.0.0"

from dff.api.module.module import *
from dff.api.types.libtypes import Argument, typeId, Parameter

class PARTITION(Module):
  """Reconstruct partitions found in a volume"""
  def __init__(self):
    Module.__init__(self, 'partition', Partition)
    self.conf.addArgument({"name": "file",
                           "description": "file containing one or more partition(s)",
	                   "input": Argument.Required|Argument.Single|typeId.Node})

    self.conf.addArgument({"name": "sector-size",
	                   "description": "The size, in bytes, of the underlying device sectors (default is 512)",
	                   "input": Argument.Optional|Argument.Single|typeId.UInt32,
                           "parameters": {"type": Parameter.Editable,
	                                  "predefined": [512, 4096]}
                           })

    self.conf.addArgument({"name": "offset",
			   "description": "offset where the volume containing the partition system starts",
	                   "input": Argument.Optional|Argument.Single|typeId.UInt64})
    
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["partition"]})
    self.tags = "Volumes"
    self.icon = ":disksfilesystems"
%}
