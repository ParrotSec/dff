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

%module  FATFS

%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "windows.i"

%{
#include "variant.hpp"
#include "vtime.hpp"
#include "node.hpp"
#include "vlink.hpp"
#include "vfile.hpp"
#include "mfso.hpp"
#include "fatfs.hpp"
#include "rootnode.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "fatfs.hpp"

%pythoncode
%{

__dff_module_fatfs_version__ = "1.0.0"

from dff.api.module.module import *
from dff.api.types.libtypes import Argument, typeId

class FATFS(Module):
  """This module create the tree contained in a fat file system, for normal and deleted files."""
  def __init__(self):
    Module.__init__(self, 'fatfs', Fatfs)
    self.conf.addArgument({"name": "file",
                           "description": "file containing a FAT file system",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "meta_carve",
                           "description": "carve directory entries in unallocated clusters (more accurate but slower)",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "check_slack",
                           "description": "This option enables to create slack space for regular files ONLY if not empty.\nIf enabled, processing is slower (default: disable)",
                           "input": Argument.Empty})
    self.conf.addConstant({"name": "mime-type",
                           "type": typeId.String,
                           "description": "managed mime type",
                           "values": ["FAT"]})
    self.tags = "File systems"
%}

