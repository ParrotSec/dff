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

#ifndef __ATTRIBUTE_HPP__
#define __ATTRIBUTE_HPP__

#include "vfs.hpp"
#include "common.hpp"

#if (defined(WIN64) || defined(WIN32))
	#if _MSC_VER >= 1600
		#include <stdint.h>
	#else
		#include "wstdint.h"
	#endif
#include <time.h>
#include <stdio.h>
#else
#include <stdint.h>
#endif

class VFile;

#ifdef WIN32
#define PACK
#else
#define PACK __attribute__((packed))
#endif

/**
 * Attribute header
 */

/* Basic attributes */
#define	ATTRIBUTE_STANDARD_INFORMATION			0x10	// Exists for every file and directory, always resident
#define	ATTRIBUTE_ATTRIBUTE_LIST			0x20
#define	ATTRIBUTE_FILE_NAME				0x30	// Always resident
#define	ATTRIBUTE_VOLUME_VERSION_OR_OBJECT_ID		0x40
#define	ATTRIBUTE_SECURITY_DESCRIPTOR			0x50
#define	ATTRIBUTE_VOLUME_NAME				0x60
#define	ATTRIBUTE_VOLUME_INFORMATION			0x70
#define	ATTRIBUTE_DATA					0x80	// Exists for every file, if content > 700 bytes : attribute becomes non-resident. If more than one $DATA attribute : additional attribute are ADS (Alternate Data Streams)
#define	ATTRIBUTE_INDEX_ROOT				0x90	// Exists for every directory. Typically have name $I30, always resident
#define	ATTRIBUTE_INDEX_ALLOCATION			0xA0	// Typically have name $I30
#define	ATTRIBUTE_BITMAP				0xB0
#define	ATTRIBUTE_SYMBOLINC_LINK_OR_REPARSE_POINT	0xC0
#define	ATTRIBUTE_EA_INFORMATION			0xD0
#define	ATTRIBUTE_EA					0xE0
#define	ATTRIBUTE_LOGGED_UTILITY_STREAM			0x100

#define ATTRIBUTE_HEADER_SIZE	16U

#define ATTRIBUTE_FLAG_COMPRESSED	0x0001
#define ATTRIBUTE_FLAG_ENCRYPTED	0x4000
#define ATTRIBUTE_FLAG_SPARSE		0x8000

#define ATTRIBUTE_END	0xFFFFFFFF

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeHeader
{
  uint32_t	attributeTypeIdentifier;
  uint32_t	attributeLength;
  uint8_t	nonResidentFlag;
  uint8_t	nameLength;
  uint16_t	nameOffset;
  uint16_t	flags;
  uint16_t	attributeIdentifier;
}		PACK AttributeHeader;

/**
 * $VOLUME_VERSION_OR_OBJECT_ID attribute
 */

#define ATTRIBUTE_ID_SIZE	16U

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeObjectID
{
  uint8_t	objectID[ATTRIBUTE_ID_SIZE];
  uint8_t	birthVolumeID[ATTRIBUTE_ID_SIZE];
  uint8_t	birthObjectID[ATTRIBUTE_ID_SIZE];
  uint8_t	birthDomainID[ATTRIBUTE_ID_SIZE];
}		PACK AttributeObjectID_t;

/**
 * $VOLUME_NAME attribute
 */

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeVolumeName
{
  uint8_t	todo;
}		PACK AttributeVolumeName_t;

/**
 * $VOLUME_INFORMATION attribute
 */

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeVolumeInformation
{
  uint8_t	todo;
}		PACK AttributeVolumeInformation_t;

/**
 * $EA_INFORMATION attribute
 */

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeEAInformation
{
  uint8_t	todo;
}		PACK AttributeEAInformation_t;

/**
 * $EA attribute
 */

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeEA
{
  uint8_t	todo;
}		PACK AttributeEA_t;

/**
 * $LOGGED_UTILITY_STREAM attribute
 */

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeLoggedUtilityStream
{
  uint8_t	todo;
}		PACK AttributeLoggedUtilityStream_t;

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_OffsetRun
{
  uint32_t	runLength;
  int64_t	runOffset;
}		PACK OffsetRun;

/**
 * Resident attribute header
 */

#define ATTRIBUTE_RESIDENT_DATA_HEADER_SIZE	6

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeResidentDataHeader
{
  uint32_t	contentSize;
  uint16_t	contentOffset;
}		PACK AttributeResidentDataHeader;

/**
 * Non-resident attribute header
 */

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeNonResidentDataHeader
{
  // AttributeHeader just before
  uint64_t	startingVCN;	// Starting and ending VCN (Virtual Cluster
  uint64_t	endingVCN;	// Number) of the run list.
  uint16_t	runListOffset;
  uint16_t	compressionUnitSize;
  uint32_t	unused;
  uint64_t	attributeContentAllocatedSize;
  uint64_t	attributeContentActualSize;
  uint64_t	attributeContentInitializedSize;
}		PACK AttributeNonResidentDataHeader;


class Attribute
{
public:
  Attribute() {};
  Attribute(VFile *);
  virtual	~Attribute();

  void			setOrigin(AttributeHeader *, uint8_t *, uint16_t,
				  uint16_t);
  uint16_t		getType();
  void			readHeader();
  void			dumpHeader();
  virtual void		content();

  void		setContent();
  // Used in case attribute is non resident
  void		setRunList();
  uint16_t	getRunListSize();
  OffsetRun	*getOffsetRun(uint16_t);
  uint16_t	getOffsetListSize();
  OffsetRun	*offsetsRuns() { return _offsetList; };
  uint16_t	setNextRun(uint16_t, uint32_t *, int64_t *);
  uint64_t	nextOffset();
  uint64_t	nextMftOffset();
  void		setDateToString(uint64_t, struct tm **, std::string *, bool);
  uint32_t	getRunAmount() { return _runAmount; };

  // For children copy constructor
  AttributeHeader	*attributeHeader() { return _attributeHeader; };
  uint8_t		*readBuffer() { return _readBuffer; };
  uint16_t		attributeOffset() { return _attributeOffset; };
  uint64_t		attributeRealOffset() { return _attributeRealOffset; };
  void			attributeRealOffset(uint64_t real) { _attributeRealOffset = real; };
  uint16_t		bufferOffset() { return _bufferOffset; };
  VFile			*vfile() { return _vfile; };
  AttributeResidentDataHeader		*residentDataHeader() { return _attributeResidentDataHeader; };
  AttributeNonResidentDataHeader	*nonResidentDataHeader() { return _attributeNonResidentDataHeader; };
  uint16_t	mftEntrySize() { return _mftEntrySize; };
  uint16_t	indexRecordSize() { return _indexRecordSize; };
  uint16_t	sectorSize() { return _sectorSize; };
  uint16_t	clusterSize() { return _clusterSize; };
  uint16_t	parentMftOffset() { return _parentMftOffset; };
  uint64_t	*fixupIndexes() { return _fixupIndexes; };
  uint16_t	fixupIndexesSize() { return _fixupIndexesSize; };
  uint64_t	baseOffset() { return _baseOffset; };

  void	mftEntrySize(uint16_t size) { _mftEntrySize = size; };
  void	indexRecordSize(uint16_t size) { _indexRecordSize = size; };
  void	sectorSize(uint16_t size) { _sectorSize = size; };
  void	clusterSize(uint16_t size) { _clusterSize = size; };

  uint64_t	offsetFromID(uint32_t);
  uint32_t	idFromOffset(uint64_t);
  void		fixupOffsets(uint8_t);
  void		fixupOffset(uint8_t, uint64_t);
  uint64_t	getFixupOffset(uint8_t);

  std::string	getName();
  std::string	getExtName();
  std::string	getFullName();
  std::string	getName(uint32_t);

protected:
  uint16_t				_parentMftOffset;
  uint16_t				_bufferOffset;
  uint16_t				_attributeOffset;
  uint8_t				*_readBuffer;
  AttributeHeader			*_attributeHeader;
  AttributeResidentDataHeader		*_attributeResidentDataHeader;
  AttributeNonResidentDataHeader	*_attributeNonResidentDataHeader;

  VFile		*_vfile;

  uint8_t	_fixupIndexesSize;
  uint64_t	*_fixupIndexes;

  // Used in case attribute is non resident
  uint64_t	_previousRunOffset;
  OffsetRun	*_offsetList;
  uint16_t	_currentRunIndex;
  uint16_t	_offsetListSize;
  uint32_t	_offsetInRun;
  uint16_t	_offsetRunIndex;
  uint8_t	_mftIndex;
  uint32_t	_runAmount;

  uint64_t	_baseOffset;
  uint64_t	_attributeRealOffset;
  uint16_t	_mftEntrySize;
  uint16_t	_indexRecordSize;
  uint16_t	_sectorSize;
  uint16_t	_clusterSize;

  uint16_t	_runList(uint16_t);
};

#endif
