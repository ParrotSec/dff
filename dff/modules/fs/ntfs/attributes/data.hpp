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
 *  Christophe Malinge <cma@digital-forensic.org>
 *
 */

#ifndef __DATA_HPP__
#define __DATA_HPP__

#include "common.hpp"
#include "attribute.hpp"
#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif



#ifdef WIN32
#define PACK
#else
#define PACK __attribute__((packed))
#endif

/**
 * $DATA attribute
 */

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeData
{
  uint8_t	todo;
}		PACK AttributeData_t;


class AttributeData : public Attribute
{
public:
  AttributeData();
  AttributeData(Attribute &);
  ~AttributeData();

  void		content();
  uint64_t	getSize() { return _size; };
  uint64_t	getInitSize() { return _attributeNonResidentDataHeader->attributeContentInitializedSize; };
  void		size(uint64_t size) { _size = size; };
  uint64_t	getOffset() { return _offset; };
  void		offset(uint64_t offset) { _offset = offset; };

  uint64_t	getAttributeOffset() { return _attributeOffset; };
  uint16_t	getSectorSize() { return _sectorSize; };

private:
  uint64_t	_size;
  uint64_t	_offset;


};

#endif
