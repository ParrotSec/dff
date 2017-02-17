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

#include <iostream>
#include <sstream>
#include <stdio.h>

#include "bitmap.hpp"

AttributeBitmap::AttributeBitmap(Attribute &parent)
{
  _attributeHeader = new AttributeHeader(*(parent.attributeHeader()));
  _readBuffer = parent.readBuffer();
  _baseOffset = 0;
  _attributeOffset = parent.attributeOffset();
  _bufferOffset = parent.bufferOffset();
  _offsetInRun = 0;
  _offsetRunIndex = 0;
  _offsetListSize = 0;

  _mftEntrySize = parent.mftEntrySize();
  _indexRecordSize = parent.indexRecordSize();
  _sectorSize = parent.sectorSize();
  _clusterSize = parent.clusterSize();
  _currentRunIndex = 0;

  if (_attributeHeader->nonResidentFlag) {
    setRunList();

    _attributeNonResidentDataHeader = new AttributeNonResidentDataHeader(*(parent.nonResidentDataHeader()));
    size(_attributeNonResidentDataHeader->attributeContentActualSize);
  }
  else {
    uint8_t	i;
    _attributeResidentDataHeader = new AttributeResidentDataHeader(*(parent.residentDataHeader()));
    size(_attributeResidentDataHeader->contentSize);
    offset(_attributeResidentDataHeader->contentOffset);
    _fixupIndexesSize = parent.fixupIndexesSize();
    _fixupIndexes = new uint64_t[_fixupIndexesSize];
    for (i = 0; i < _fixupIndexesSize; i++) {
      _fixupIndexes[i] = parent.fixupIndexes()[i];
    }
  }
}

AttributeBitmap::~AttributeBitmap()
{
  ;
}

template <typename T>	std::ostringstream	&AttributeBitmap::bin(T &value, std::ostringstream &o)
{
  for (T bit = highbit(bit); bit; bit >>= 1 )
    {
      o << ( ( value & bit ) ? '1' : '0' );
    }
  return o;
}

void			AttributeBitmap::content()
{
  uint32_t		i = 0;
  std::ostringstream	bitmap;

  bitmap.str("");
  while (i < _size) {
    bitmap << std::hex << std::setw(2) << std::setfill('0') << (uint16_t)(*(uint8_t *)(_readBuffer + _attributeOffset + _offset + i));
    if (i % 2) {
      bitmap << ' ';
    }
    i++;
  }
  printf("\t%s\n", bitmap.str().c_str());
  bitmap.str("");
  i = 0;
  while (i < _size) {
    
    //    bitmap << std::binary((uint16_t)(*(uint8_t *)(_readBuffer + _attributeOffset + _offset + i)));
    //    bin(
    uint8_t val = (uint8_t)(*(uint8_t *)(_readBuffer + _attributeOffset + _offset + i));
    bin(val, bitmap);
    if (i % 2) {
      bitmap << std::endl << "\t";
    }
    i++;
  }
  printf("\t%s\n", bitmap.str().c_str());
}

