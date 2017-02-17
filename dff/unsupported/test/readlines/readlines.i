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

%module  READLINES
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "windows.i"

%{
#include "variant.hpp"
#include "vtime.hpp"
#include "fso.hpp"
#include "mfso.hpp"
#include "node.hpp"
#include "vlink.hpp"
#include "vfile.hpp"
#include "rootnode.hpp"
#include "readlines.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "readlines.hpp"


%pythoncode
%{

__dff_module_READLINES_version__ = "1.0.0"

from dff.api.module.module import *
from dff.api.types.libtypes import *
from dff.api.vfs import vfs
class READLINES(Module):
  """Add file from your operating system to the VFS"""
  def __init__(self):
    Module.__init__(self, 'readlines', readlines)
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node, 
	                   "name": "file", 
	                   "description": "text file to read lines",
                          })
    self.tags = "Connectors"
%}
