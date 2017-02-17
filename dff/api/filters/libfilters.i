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
 *  Frederic B. <fba@digital-forensic.org>
 */

#include "pyrun.swg"

%module(package="dff.api.filters") libfilters

#ifndef WIN32
%include "stdint.i"
#else
%include "wstdint.i"
#endif

%include "std_string.i"
%include "std_map.i"
%include "std_vector.i"
%include "windows.i"

%exception Filter::process
{
  SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  $action
  SWIG_PYTHON_THREAD_END_BLOCK;
}


%{
#include "variant.hpp"
#include "vtime.hpp"
#include "node.hpp"
#include "vlink.hpp"
#include "vfile.hpp"
#include "mfso.hpp"
#include "factory.hpp"
#include "rootnode.hpp"
/* #include "../include/export.hpp" */
/* #include "../include/eventhandler.hpp" */
#include "../include/filter.hpp"
#include "dictionnary.hpp"
%}

%import "../vfs/libvfs.i"

namespace std
{
  %template(BadPatterns)            std::vector<BadPattern*>;
  %template(VectString)             std::vector<std::string>;
  %template(Dictionnaries)          std::map<std::string, Dictionnary* >;
};

%traits_swigtype(Dictionnary);
%fragment(SWIG_Traits_frag(Dictionnary));


%include "../include/filter.hpp"
%include "factory.hpp"
%include "dictionnary.hpp"

