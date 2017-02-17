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

#ifndef __BITMAP_HPP__
#define __BITMAP_HPP__

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
 * $BITMAP attribute
 */

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeBitmap
{
  uint8_t	todo;
}		PACK AttributeBitmap_t;


class AttributeBitmap : public Attribute
{
public:
  AttributeBitmap(Attribute &);
  ~AttributeBitmap();  
  void	content();
  //  uint64_t	nextOffset();
  void	size(uint64_t size) { _size = size; };
  void		offset(uint64_t offset) { _offset = offset; };
  template <typename T> inline T highbit(T &t) { return t = (((T)(-1)) >> 1) + 1; };
  template <typename T> std::ostringstream	&bin(T &, std::ostringstream &);

private:
  uint64_t	_currentOffset;
  uint64_t	_size;
  uint64_t	_offset;
};


#endif
