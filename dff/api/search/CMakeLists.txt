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
#  Frederic Baguelin <fba@digital-forensic.org>

if (TRE_FOUND)
  set(search_files __init__.py)
  if(WIN32)
    file(COPY ${TRE_DYN_LIBRARIES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
    set(search_files ${search_files} tre.dll)
  endif(WIN32)
  set(link_libraries ${TRE_LIBRARY})
endif (TRE_FOUND)

dff_cpp_api(search
  CPP_FILES search.cpp boyer_moore.cpp
  SWIG_FILE libsearch.i
  LINK_LIBRARIES ${link_libraries}
  EXTRA_FILES ${search_files}
  )
