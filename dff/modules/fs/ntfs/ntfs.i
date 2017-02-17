/* 
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 * 
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
 *  Christophe Malinge <cma@digital-forensic.org>
 *
 */

#include "pyrun.swg"

%module  NTFS 
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
#include "rootnode.hpp"
#include "ntfs.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "ntfs.hpp"

%pythoncode
%{

__dff_module_NTFS_version__ = "0.5.1"

from dff.api.module.module import *
from dff.api.types.libtypes import Argument, typeId

class NTFS(Module):
  def __init__(self):
    Module.__init__(self, 'ntfs', Ntfs)
    self.conf.addArgument({"name": "file",
                           "description": "file containing a NTFS file system",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "mftdecode",
	                   "description": "Only try to decode mft at this offset",
                           "input": Argument.Optional|Argument.Single|typeId.UInt64})
    self.conf.addArgument({"name": "indexdecode",
	                   "description": "Only try to decode index records at this offset",
                           "input": Argument.Optional|Argument.Single|typeId.UInt64})
    self.conf.addArgument({"name": "no-orphan",
                           "description": "Don't check for orphaned or deleted files",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "no-bitmap-parse",
                           "description": "Don't parse the top-level $Bitmap NTFS metafile to create a node filled with unallocated space",
                           "input": Argument.Empty})
    self.conf.addConstant({"name": "mime-type", 
                           "type": typeId.String,
                           "description": "managed mime type",
                           "values": ["NTFS"]})
    self.conf.description = "Creates a tree from a NTFS file system, for regular and deleted/orphan files.\nIt also provides human-readable dump of MFT or Indexex entries."
    self.tags = "File systems"
%}
