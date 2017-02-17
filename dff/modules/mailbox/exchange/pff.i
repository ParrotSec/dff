/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal J. <sja@digital-forensic.org>
 */

#include "pyrun.swg"

%module PFF 
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
#include "pff.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "pff.hpp"

%pythoncode
%{
from dff.api.module.module import *
from dff.api.types.libtypes import *
class PFF(Module):
  """Extract PST/PAB/OST mailbox content."""
  def __init__(self):
    Module.__init__(self, 'exchange', pff)
    self.conf.addArgument({"input":Argument.Required|Argument.Single|typeId.Node,
                           "name": "file",
                           "description": "Path to mailbox file"})
    self.conf.addArgument({"name":"unallocated",
                           "description":"Don't search for unallocated data",
                           "input": Argument.Empty})
    self.conf.addArgument({"name":"recoverable",
                           "description":"Don't search for recoverable items",
                           "input": Argument.Empty})
    self.conf.addArgument({"name":"orphan",
                           "description":"Don't search for oprhan items",
                           "input": Argument.Empty})
    self.conf.addArgument({"name":"default",
                           "description":"Don't create (allocated) items",
                           "input": Argument.Empty})
    self.conf.addConstant({"name":"mime-type",
                           "type":typeId.String,
                           "description":"managed mime type",
                           "values":["Outlook"]})
    self.tags = "Mailbox"
    self.icon = ":mailbox" 
%}
