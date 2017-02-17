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

if(WIN32)
  set(ewf_files ${EWF_DYN_LIBRARIES})
  set(definitions -D_LIBEWF_TYPES_H_INTEGERS)
endif(WIN32)

dff_cpp_module(EWF
  CPP_FILES ewf.cpp ewfnode.cpp
  SWIG_FILE ewf.i
  DEFINITIONS ${definitions}
  LINK_LIBRARIES exceptions types vfs ${EWF_LIBRARY}
  INCLUDE_DIRS ${EWF_INCLUDE_DIR}
  EXTRA_FILES ${ewf_files}
  )
