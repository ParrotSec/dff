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

%module(package="dff.api.datatype", directors="1") libdatatype

%feature("director") DataTypeHandler;

%ignore dff::vector;
%ignore dff::map;
%ignore dff::Mutex;
%ignore dff::ScopedMutex;

#ifndef WIN32
%include "stdint.i"
#else
%include "wstdint.i"
#endif
%include "std_string.i"
%include "std_list.i"
%include "std_map.i"
%include "windows.i"

%feature("ref") RCObj "$this->addref();"
%feature("unref") RCObj "$this->delref();"


%{
#include "export.hpp"
#include "datatype.hpp"
%}
%include "../include/export.hpp"
%include "../include/datatype.hpp"

namespace std
{
  %template(ListDataType)       list<DataTypeHandler*>;
  %template(MapDataType)        map<std::string, uint32_t>;
}
