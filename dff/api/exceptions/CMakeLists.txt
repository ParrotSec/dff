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
#  Solal Jacob <sja@digital-forensic.org>


dff_cpp_api(exceptions
  CPP_FILES exceptions.cpp
  SWIG_FILE libexceptions.i
  EXTRA_FILES __init__.py
  )

if (UNIX)
  add_custom_target(patchexceptions ALL
    DEPENDS ${SWIG_MODULE_libexceptions_REAL_NAME}
    COMMENT "Patching libexceptions.py"
    COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/patch.py
    ${CMAKE_CURRENT_BINARY_DIR}/libexceptions.py
    )
elseif(UNIX)
  add_custom_target(patchexceptions ALL
    DEPENDS ${SWIG_MODULE_libexceptions_REAL_NAME}
    COMMENT "Patching libexceptions.py"
    COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/patch.py
    ${CMAKE_CURRENT_BINARY_DIR}/libexceptions.py
    )
endif(UNIX)

add_dependencies("dff.api.exceptions" patchexceptions)