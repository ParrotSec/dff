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

#ifndef __INDEXROOT_HPP__
#define __INDEXROOT_HPP__

#include "common.hpp"
#include "attribute.hpp"

#ifdef WIN32
#define PACK
#else
#define PACK __attribute__((packed))
#endif


/**
 * $INDEX_ROOT attribute
 */

#define ATTRIBUTE_INDEXROOT_SIZE	16

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeIndexRoot
{
  uint32_t	attributeInIndexType;	// 0 if this entry does not use an attribute
  uint32_t	collationSortingRule;
  uint32_t	indexRecordSizeBytes;
  uint8_t	indexRecordSizeClusters;
  uint8_t	unused[3];
}		PACK AttributeIndexRoot_t;


/**
 * Node header following IndexRoot header
 */

#define	NODEHEADER_SIZE	16

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_NodeHeader
{
  uint32_t	relOffsetStart;		// Offset to start of index entry list, rel to start of node header
  uint32_t	relOffsetEndUsed;	// Offset to end of index entry list used area
  uint32_t	relOffsetEndAlloc;
  uint32_t	flags;			// only 0x01, if this entry has children nodes
}		PACK NodeHeader;


/**
 * Generic Index entry
 */

#define	ENTRY_CHILD_NODE_EXIST	0x01
#define ENTRY_LAST_ONE		0x02

#define ENTRY_VCN_RELATIVE_OFFSET	-8

#define INDEX_ENTRY_SIZE	16

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	IndexEntry
{
  uint64_t	undefined;
  uint16_t	entryLength;
  uint16_t	contentLength;
  uint32_t	flags;		// 0x01 or 0x02
  // content
  // last 8 bytes is starting VCN of child node in $INDEX_ALLOCATION (if flag set),
  //  on an 8-byte boundary
}		PACK IndexEntry;

/**
 * Directory Index entry
 */

#define DIRECTORY_INDEX_ENTRY_SIZE	16

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	DirectoryIndexEntry
{
  uint64_t	fileNameMFTFileReference;
  uint16_t	entryLength;
  uint16_t	fileNameLength;
  uint32_t	flags;		// same as above
  // content
  // last 8 bytes is starting VCN of child node in $INDEX_ALLOCATION (if flag set),
  //  on an 8-byte boundary

}		PACK DirectoryIndexEntry;

class AttributeIndexRoot : Attribute
{
public:
  AttributeIndexRoot(Attribute &);
  ~AttributeIndexRoot();
  void		content();
  uint32_t	indexRecordSizeBytes();
  bool		hasNext();
  AttributeIndexRoot_t	*data() { return _data; };
  NodeHeader	*nodeHeader() { return _nodeHeader; };
  uint32_t	currentEntryOffset() { return _currentRelativeOffset; };
  uint32_t	currentEntryLength();
  uint32_t	nextMftEntry();
  uint32_t	entriesAmount() { return _entriesAmount; };
  bool		canGetNext();

private:
  AttributeIndexRoot_t	*_data;
  NodeHeader		*_nodeHeader;
  IndexEntry		**_indexEntries;
  uint8_t		**_entriesContent;
  uint16_t		_currentIndexEntry;
  uint32_t		_currentLength;

  uint32_t	_currentRelativeOffset;
  uint32_t	_baseReadingOffset;
  uint32_t	_currentMftEntry;
  uint64_t	_nextVCN;
  bool		_lastEntryFound;
  uint32_t	_entriesAmount;

  uint32_t	_saveEntries();  
};

#endif
