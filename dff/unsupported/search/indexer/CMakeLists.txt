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
#  Romain Bertholon <rbe@digital-forensic.org>
#  Christophe Malinge <cma@digital-forensic.org>

if(${CLUCENE_CONFIG_INCLUDE_PATH} AND ${CLUCENE_LIBRARY})
  find_package(SWIG REQUIRED)
  include(${SWIG_USE_FILE})

  include_directories(${PYTHON_INCLUDE_PATH} ${QT_INCLUDE_DIR} ${QT_QTCORE_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_HOME_DIRECTORY}/api/include ${CMAKE_HOME_DIRECTORY}/api/tree ${CMAKE_HOME_DIRECTORY}/api/index/ ${CMAKE_HOME_DIRECTORY}/api/index/CLucene ${CLUCENE_CONFIG_INCLUDE_PATH})

  set(indexer_srcs
    indexer.cpp
    )
  
  set_source_files_properties(indexer.i PROPERTIES CPLUSPLUS ON)
  swig_add_module(INDEXER python indexer.i ${indexer_srcs})
  if (UNIX)
    swig_link_libraries(INDEXER ${PYTHON_LIBRARIES} exceptions vfs tree libindex)
  else (UNIX)
    swig_link_libraries(INDEXER ${PYTHON_LIBRARIES} exceptions vfs tree libindex ${QT_QTCORE_LIBRARIES} ${QT_QTCLUCENE_LIBRARIES})
  endif (UNIX)
  
  if(CMAKE_GENERATOR MATCHES "Visual Studio")
    set_target_properties(${SWIG_MODULE_INDEXER_REAL_NAME} PROPERTIES
      PREFIX "../"
      SUFFIX ".pyd"
      )
  endif(CMAKE_GENERATOR MATCHES "Visual Studio")
  
  set(indexer_files
    INDEXER.py
    )
  
  install_lib(${SWIG_MODULE_INDEXER_REAL_NAME})
  install_file(indexer ${indexer_files})
endif(${CLUCENE_CONFIG_INCLUDE_PATH} AND ${CLUCENE_LIBRARY})
