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

#ifndef __ATTRIBUTELIST_HPP__
#define __ATTRIBUTELIST_HPP__

#include "common.hpp"
#include "attribute.hpp"

#ifdef WIN32
#define PACK
#else
#define PACK __attribute__((packed))
#endif

/**
 * $ATTRIBUTE_LIST attribute
 *  Used for files that have attribute headers that will not fit into one
 *  MFT entry, contains a list with an entry for every attribute in the file
 *  or directory.
 *
 * windows/system32 have it
 */

#define ATTRIBUTE_ATTRIBUTE_LIST_SIZE	25

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeAttributeList
{
  uint32_t	attributeType;
  uint16_t	entryLength;
  uint8_t	nameLength;
  uint8_t	nameOffset;	// relative to start of this entry
  uint64_t	startingVCNInAttribute;
  uint64_t	fileReference;	// file reference where attribute is located
  uint8_t	attributeID;
}		PACK AttributeAttributeList_t;

class AttributeAttributeList : Attribute
{
public:
  AttributeAttributeList(VFile *, Attribute &);
  ~AttributeAttributeList();

  void		content();
  void		setMftEntry(uint32_t id) { _id = id; };
  uint32_t	getExternalAttributeIndexRoot();
  uint32_t	getExternalAttributeIndexAlloc();
  uint32_t	getExternalAttributeFileName();
  uint32_t	getExternalAttributeData();
  void		size(uint64_t size) { _size = size; };
  void		offset(uint64_t offset) { _offset = offset; };

private:
  AttributeAttributeList_t	*_data;
  uint32_t	_id;
  uint32_t	_currentEntry;
  uint16_t	_dataOffset;
  uint64_t	_size;
  uint64_t	_offset;
  uint8_t	*_contentBuffer;
};

#endif
