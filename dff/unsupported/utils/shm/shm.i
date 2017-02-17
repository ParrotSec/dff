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
 *  Solal J. <sja@digital-forensic.org>
 */

#include "pyrun.swg"

%module SHM 
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "windows.i"

%{
#include "variant.hpp"
#include "vtime.hpp"
#include "shm.hpp"
#include "rootnode.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "shm.hpp"

%pythoncode
%{

__dff_module_shm_version__ = "1.0.0"

from dff.api.module.module import *
from dff.api.types.libtypes import Argument, typeId

class SHM(Module):
  """SHM create a copy of the parent file to a new node named filename.\
It permit to have access to file with write permission without doing any modification in any other files.\n\
SHM create files stored in RAM so don't use it for huge files.\n\
SHM is also used by other modules (zip, touch, ...) to create file with content in the VFS in fast way.\n"""
  def __init__(self):
    Module.__init__(self, 'shm', Shm)
    self.conf.addArgument({"input": Argument.Single|Argument.Required|typeId.String,
	                   "name": "filename",
	                   "description": "file name of the created file"}) 
    self.conf.addArgument({"input": Argument.Single|Argument.Required|typeId.Node,
	                   "name": "parent",
	                   "description": "file to copy"})
    self.tags = "Utils"
%}


