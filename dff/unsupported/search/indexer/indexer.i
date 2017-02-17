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
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

#include "pyrun.swg"

%module  INDEXER
#ifndef WIN32
%include "stdint.i"
#else
%include "wstdint.i"
#endif
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "windows.i"


%{
#include "variant.hpp"
#include "vtime.hpp"
#include "mfso.hpp"
#include "node.hpp"
#include "vfile.hpp"
#include "vlink.hpp"
#include "index.hpp"
#include "indexer.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "indexer.hpp"

/*
namespace std
{
}; */

%pythoncode
%{
from dff.api.module.module import *
from dff.api.types.libtypes import Argument, typeId, Variant, Parameter
from dff.ui.conf import Conf
from PyQt4.QtCore import QDir

class INDEXER(Module):
  """This module is a dff module."""
  def __init__(self):
    Module.__init__(self, 'indexer', Indexer)

    self.dff_conf = Conf()
    path = self.dff_conf.index_path

    self.conf.addArgument({"name": "node",
                           "description": "dir to index",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.String,
			   "name": "index",
                           "description": "directory where the index will be stored",
			   "parameters": {"type": Parameter.NotEditable,
			   		 "predefined": [str(path)]}
			   })
    self.tags = "Search"
    self.icon = ":index"
%}
