# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
#
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
#  Christophe Malinge <cma@digital-forensic.org>

include_directories(${ICU_INCLUDE_DIRS})

#add_definitions(-Wall -Wunused -Wextra)

dff_cpp_module(NTFS
  CPP_FILES ntfs.cpp
  boot.cpp
  mftentry.cpp
  mftfile.cpp
  attribute.cpp
  ntfsnode.cpp
  bitmapnode.cpp
  attributes/data.cpp
  attributes/bitmap.cpp
  attributes/filename.cpp
  attributes/standardinformation.cpp
  attributes/attributelist.cpp
  attributes/indexroot.cpp
  attributes/reparsepoint.cpp
  attributes/indexallocation.cpp
  attributes/securitydescriptor.cpp
  SWIG_FILE ntfs.i
  INCLUDE_DIRS ${ICU_INCLUDE_DIRS}
  LINK_LIBRARIES ${ICU_LIBRARIES} exceptions types vfs
  )
