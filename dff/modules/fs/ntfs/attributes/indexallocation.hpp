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

#ifndef __INDEXALLOCATION_HPP__
#define __INDEXALLOCATION_HPP__

#include "common.hpp"
#include "attribute.hpp"
#include "attributes/indexroot.hpp"

#ifdef WIN32
#define PACK
#else
#define PACK __attribute__((packed))
#endif
/**
 * $INDEX_ALLOCATION attribute
 */

#define ATTRIBUTE_IA_SIGNATURE	"INDX"
#define ATTRIBUTE_IA_SIZE	24

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeIndexAllocation
{
  char		signature[4];
  uint16_t	fixupArrayOffset;
  uint16_t	fixupAmount;
  uint64_t	sequenceNumber;	//$Logfile LSN
  uint64_t	recordVCN; // The VCN of this record in the full index stream
}		PACK AttributeIndexAllocation_t;


class AttributeIndexAllocation : public Attribute
{
public:
  AttributeIndexAllocation(VFile *, uint64_t);
  AttributeIndexAllocation(Attribute &);
  ~AttributeIndexAllocation();
  void	content();

  void		fillRecords(uint32_t, uint32_t, uint32_t);
  uint32_t	readNextIndex();
  uint32_t	getEntryOffset();
  NodeHeader	*getNodeHeader() { return _nodeHeader; };
  uint64_t	realOffset() { return _realOffset; };
  void		dumpHeader();
  void		dumpNodeHeader();
  void		dumpEntries();

private:
  AttributeIndexAllocation_t	*_data;
  NodeHeader			*_nodeHeader;
  //  uint16_t	_sectorSize;
  //  uint16_t	_clusterSize;
  //  uint16_t	_indexRecordSize;
  uint64_t	_realOffset;
  uint8_t	*_contentBuffer;
  uint32_t	_contentBufferOffset;
  uint32_t	_entryOffset;

  uint16_t	*_fixupValues;
  uint16_t	_fixupSignature;

  bool		_hasMoreAllocation();
};

#endif
