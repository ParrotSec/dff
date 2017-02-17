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

#ifndef __MFTENTRY_HPP__
#define __MFTENTRY_HPP__

#include "vfs.hpp"
#include "common.hpp"
#include "attribute.hpp"
#include "attributes/bitmap.hpp"
#include "attributes/data.hpp"
#include "attributes/filename.hpp"
#include "attributes/indexroot.hpp"
#include "attributes/standardinformation.hpp"
#include "attributes/reparsepoint.hpp"
#include "attributes/attributelist.hpp"
#include "attributes/indexallocation.hpp"

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

#define MFTENTRY_HEADER_SIZE	42
#define	MFTENTRY_SIGNATURE	"FILE"
#define MFTENTRY_ROOT		0x5

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_MftEntryBlock
{
  char		signature[4];
  uint16_t	fixupArrayOffset;
  uint16_t	fixupNumber; // TODO rename fixupAmount
  uint64_t	logFileLSN; // Long File Sequence number
  uint16_t	sequenceValue;
  uint16_t	linkCount;
  uint16_t	firstAttributeOffset;
  uint16_t	flag; // in use directory
  uint32_t	usedSizeMftEntry;
  uint32_t	allocatedSizeMftEntry;
  uint64_t	fileReferenceToBaseRecord;
  uint16_t	nextAttributeId;
  uint16_t	unused;
  uint16_t	fileRef;
  //uint8_t	attributesAndFixupValues[982];
}		PACK MftEntryBlock;

class MftEntry
{
public:
  MftEntry(VFile *);
  ~MftEntry();
  bool		isMftEntryBlock(uint64_t);
  MftEntryBlock	*getMftEntryBlock();
  void		dumpHeader();
  bool		decode(uint64_t);
  uint16_t	setNextRun(uint16_t, uint32_t *, uint64_t *);
  Attribute	*getNextAttribute();
  void		dumpAttribute(Attribute *);
  uint16_t	discoverMftEntrySize(uint64_t);

  uint16_t	clusterSize() { return _clusterSize; };
  uint16_t	mftEntrySize() { return _mftEntrySize; };
  uint16_t	indexRecordSize() { return _indexRecordSize; };	// For BTrees
  uint16_t	sectorSize() { return _sectorSize; };		// For Fixup
  void		clusterSize(uint16_t);
  void		mftEntrySize(uint16_t);
  void		indexRecordSize(uint16_t);	// For BTrees
  void		sectorSize(uint16_t);		// For Fixup

  void		_fixFixup();
  void		dumpChunks(OffsetRun *, uint16_t);

  void		continueAt(uint16_t, uint16_t);
  uint16_t	bufferOffset() { return _bufferOffset; };
  uint16_t	attributeOffset() { return _attributeOffset; };
  void		close();

private:
  VFile					*_vfile;
  MftEntryBlock		       		*_mftEntryBlock;

  Attribute				*_currentAttribute;
  AttributeHeader			*_attributeHeader;

  uint16_t	_clusterSize;
  uint16_t	_mftEntrySize;
  uint16_t	_indexRecordSize;
  uint16_t	_sectorSize;

  uint8_t	*_readBuffer;
  uint16_t	_bufferOffset;
  uint64_t	_previousReadOffset;
  uint16_t	_attributeOffset;
  uint16_t	_fixupSignature;
  uint16_t	*_fixupValues;
  uint64_t	_previousRunOffset;
  uint16_t	_entryOffset;

  uint16_t	_runList(uint16_t);
  bool		_validateSignature();
  void		_bufferedRead(uint64_t);
  void		_bufferedRead(uint64_t, uint32_t);
  //  void		_setDateToString(uint64_t, struct tm **, std::string *);
};


#endif
