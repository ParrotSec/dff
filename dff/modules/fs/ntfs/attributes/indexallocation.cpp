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

#include <stdio.h>

#include "vfile.hpp"
#include "indexallocation.hpp"
#include "attributes/filename.hpp"

AttributeIndexAllocation::AttributeIndexAllocation(VFile *vFile, uint64_t indexAllocOffset)
{
  _vfile = vFile;
  _baseOffset = indexAllocOffset;
  _indexRecordSize = 4096;
  _sectorSize = 512;
  _contentBuffer = new uint8_t[_indexRecordSize];
  _vfile->seek(_baseOffset);
  _vfile->read(_contentBuffer, _indexRecordSize);
  _data = (AttributeIndexAllocation_t *)(_contentBuffer);
  _contentBufferOffset = 0;

  dumpHeader();

  //fixup
  if (_data->fixupAmount > 0) {
    uint8_t	i;
    uint8_t	lbreak = 0;

    i = 0;
    DEBUG(INFO, "Fixup register\n");
    _fixupValues = new uint16_t[_data->fixupAmount];
    _contentBufferOffset += _data->fixupArrayOffset;
    _fixupSignature = *(uint16_t *)(_contentBuffer + _contentBufferOffset);
    DEBUG(INFO, "\tfixupSignature: 0x%.4x\n", _fixupSignature);
    _contentBufferOffset += SIZE_2BYTES;
    while (i < _data->fixupAmount) {
      _fixupValues[i] = *(uint16_t *)(_contentBuffer + _contentBufferOffset);
      DEBUG(INFO, "\tfixupValue #%u: 0x%.4x\n", i, _fixupValues[i]);
      _contentBufferOffset += SIZE_2BYTES;
      i++;
      if (lbreak++ == 255)
	break;
    }

  DEBUG(INFO, "Fixup validate and set\n");
    i = 0;
    lbreak = 0;
    while (i < _data->fixupAmount - 1) {
      uint16_t	*valToFix = (uint16_t *)(_contentBuffer + ((i + 1) * _sectorSize) - 2);
      DEBUG(INFO, "\tGot: 0x%.4x\n", *valToFix);
      *valToFix = _fixupValues[i];
      DEBUG(INFO, "\tWrote: 0x%.4x\n", *valToFix);
      i++;
      if (lbreak++ == 255)
	break;

    }
  }

  _nodeHeader = (NodeHeader *)(_contentBuffer + ATTRIBUTE_IA_SIZE);
  _entryOffset = ATTRIBUTE_IA_SIZE + _nodeHeader->relOffsetStart;
}

AttributeIndexAllocation::AttributeIndexAllocation(Attribute &parent)
{
  _attributeHeader = new AttributeHeader(*(parent.attributeHeader()));
  _readBuffer = parent.readBuffer();
  _baseOffset = parent.baseOffset();
  _attributeOffset = parent.attributeOffset();
  _bufferOffset = parent.bufferOffset();
  _offsetInRun = 0;
  _offsetRunIndex = 0;
  _offsetListSize = 0;
  _vfile = parent.vfile();

  _mftEntrySize = parent.mftEntrySize();
  _indexRecordSize = parent.indexRecordSize();
  _sectorSize = parent.sectorSize();
  _clusterSize = parent.clusterSize();
  _currentRunIndex = 0;
  DEBUG(INFO, "setting clustersize to 0x%x\n", _clusterSize);

  _entryOffset = 0;
  _nodeHeader = NULL;

  _parentMftOffset = parent.parentMftOffset();
  
  if (_attributeHeader->nonResidentFlag) {
    setRunList();
#if __WORDSIZE == 64
    DEBUG(INFO, "run amount1 0x%lx\n", offsetsRuns()[0].runOffset);
#else
    DEBUG(INFO, "run amount1 0x%llx\n", offsetsRuns()[0].runOffset);
#endif
  }
}

AttributeIndexAllocation::~AttributeIndexAllocation()
{
  ;
}

/**
 * Also fill buffer of first records
 */
void		AttributeIndexAllocation::fillRecords(uint32_t sectorSize,
						      uint32_t clusterSize,
						      uint32_t indexRecordSize)
{
  uint8_t	i;
  uint8_t	lbreak = 0;

#if __WORDSIZE == 64
  DEBUG(INFO, "run amount2 0x%lx\n", offsetsRuns()[0].runOffset);
#else
  DEBUG(INFO, "run amount2 0x%llx\n", offsetsRuns()[0].runOffset);
#endif

  _indexRecordSize = indexRecordSize;
  _sectorSize = sectorSize;
  _clusterSize = clusterSize;

  if (_attributeHeader->nonResidentFlag) {
    _realOffset = nextOffset();// * _indexRecordSize;
  }
  else {
#if __WORDSIZE == 64
    DEBUG(INFO, "0x%lx 0x%x 0x%x\n", _baseOffset, _attributeOffset, _bufferOffset);
#else
    DEBUG(INFO, "0x%llx 0x%x 0x%x\n", _baseOffset, _attributeOffset, _bufferOffset);
#endif
    ;
  }
  _contentBuffer = new uint8_t[_indexRecordSize];
  _contentBufferOffset = 0;
#if __WORDSIZE == 64
  DEBUG(INFO, "Reading 0x%x bytes IndexAllocation @ 0x%lx\n", _indexRecordSize, _realOffset);
#else
  DEBUG(INFO, "Reading 0x%x bytes IndexAllocation @ 0x%llx\n", _indexRecordSize, _realOffset);
#endif

  _vfile->seek(_realOffset);
  _vfile->read(_contentBuffer, _indexRecordSize);

  _data = (AttributeIndexAllocation_t *)_contentBuffer;

  if (_data->fixupArrayOffset >= _indexRecordSize || (_data->fixupAmount * sectorSize) > _indexRecordSize + sectorSize) {
    _nodeHeader = NULL;
    return ;
  }
    
  // TODO validate signature
  DEBUG(INFO, "fixupArrayOffset: 0x%x\n", _data->fixupArrayOffset);
  DEBUG(INFO, "fixupAmount: 0x%x\n", _data->fixupAmount);
#if __WORDSIZE == 64
  DEBUG(INFO, "sequenceNumber 0x%.16lx\n", _data->sequenceNumber);
  DEBUG(INFO, "VCN of this record: 0x%.16lx\n", _data->recordVCN);
#else
  DEBUG(INFO, "sequenceNumber 0x%.16llx\n", _data->sequenceNumber);
  DEBUG(INFO, "VCN of this record: 0x%.16llx\n", _data->recordVCN);
#endif

  //fixup
  if (_data->fixupAmount > 0) {
    i = 0;
    _fixupValues = new uint16_t[_data->fixupAmount];
    _contentBufferOffset += _data->fixupArrayOffset;
    _fixupSignature = *(uint16_t *)(_contentBuffer + _contentBufferOffset);
    DEBUG(INFO, "fixupSignature: 0x%.4x\n", _fixupSignature);
    _contentBufferOffset += SIZE_2BYTES;
    while (i < _data->fixupAmount) {
      _fixupValues[i] = *(uint16_t *)(_contentBuffer + _contentBufferOffset);
      DEBUG(INFO, "fixupValue: 0x%.4x\n", _fixupValues[i]);
      _contentBufferOffset += SIZE_2BYTES;
      i++;
      if (lbreak++ == 255)
	break;
    }

    i = 0;
    lbreak = 0;
    while (i < _data->fixupAmount - 1) {
      uint16_t	*valToFix = (uint16_t *)(_contentBuffer + ((i + 1) * _sectorSize) - 2);
      DEBUG(INFO, "Got: 0x%.4x\n", *valToFix);
      *valToFix = _fixupValues[i];
      DEBUG(INFO, "Wrote: 0x%.4x\n", *valToFix);
      i++;
      if (lbreak++ == 255)
	break;

    }
  }

  _nodeHeader = (NodeHeader *)(_contentBuffer + ATTRIBUTE_IA_SIZE);
  _entryOffset = ATTRIBUTE_IA_SIZE + _nodeHeader->relOffsetStart;
}

bool	AttributeIndexAllocation::_hasMoreAllocation()
{
  uint8_t	i;
  uint8_t	lbreak = 0;
  uint8_t	chunckShift = _indexRecordSize / _clusterSize;

  if (_currentRunIndex >= getOffsetRun(_offsetRunIndex)->runLength && (_offsetRunIndex + 1) >= _offsetListSize) {
    return false;
  }

  // FIXME getting next indexallocation is not reliable if _indexRecordSize > _clusterSize,
  // except if chunck are NOT fragmented.
  while (chunckShift) {
    if (!(_realOffset = nextOffset())) {
      return false;
    }
    chunckShift--;
  }

  delete _contentBuffer;
  _contentBuffer = new uint8_t[_indexRecordSize];
  _contentBufferOffset = 0;

#if __WORDSIZE == 64
  DEBUG(INFO, "Reading 0x%x bytes IndexAllocation @ 0x%lx\n", _indexRecordSize, _realOffset);
#else
  DEBUG(INFO, "Reading 0x%x bytes IndexAllocation @ 0x%llx\n", _indexRecordSize, _realOffset);
#endif
  _vfile->seek(_realOffset);
  _vfile->read(_contentBuffer, _indexRecordSize);

  _data = (AttributeIndexAllocation_t *)_contentBuffer;

  DEBUG(INFO, "fixup amount is %u attribute is non-resident ? %u\n", _data->fixupAmount, _attributeHeader->nonResidentFlag);
  if (!(_attributeHeader->nonResidentFlag) && _data->fixupAmount > 0) {
    i = 0;
    delete _fixupValues;
    _fixupValues = new uint16_t[_data->fixupAmount];
    _contentBufferOffset += _data->fixupArrayOffset;
    _fixupSignature = *(uint16_t *)(_contentBuffer + _contentBufferOffset);
    _contentBufferOffset += SIZE_2BYTES;
    while (i < _data->fixupAmount) {
      _fixupValues[i] = *(uint16_t *)(_contentBuffer + _contentBufferOffset);
      _contentBufferOffset += SIZE_2BYTES;
      i++;
      if (lbreak++ == 255)
	break;
    }

    i = 0;
    lbreak = 0;
    while (i < _data->fixupAmount - 1) {
      uint16_t	*valToFix = (uint16_t *)(_contentBuffer + ((i + 1) * _sectorSize) - 2);
      *valToFix = _fixupValues[i];
      i++;
      if (lbreak++ == 255)
	break;
    }
  }

  _nodeHeader = (NodeHeader *)(_contentBuffer + ATTRIBUTE_IA_SIZE);
  _entryOffset = ATTRIBUTE_IA_SIZE + _nodeHeader->relOffsetStart;
  return true;
}
 
uint32_t	AttributeIndexAllocation::getEntryOffset()
{
  if (_nodeHeader == NULL) {
    return 0;
  }

  uint16_t	end = _nodeHeader->relOffsetEndUsed;

  if (_entryOffset >= end || _entryOffset >= _indexRecordSize) {
    DEBUG(INFO, "before 0x%x\n", _nodeHeader->relOffsetEndUsed);
    if (!(_hasMoreAllocation())) {
      DEBUG(INFO, "after 0x%x\n", _nodeHeader->relOffsetEndUsed);
      DEBUG(INFO, "no more indexalloc end is 0x%x\n", end);
      //      return end;
      return _nodeHeader->relOffsetEndUsed;
    }
  }
  // FIXME : Validate INDX signature !
  if (_entryOffset >= _nodeHeader->relOffsetEndUsed || _entryOffset >= _indexRecordSize) {
    while (_nodeHeader && _nodeHeader->relOffsetEndUsed && _hasMoreAllocation() && _entryOffset > _nodeHeader->relOffsetEndUsed) {
      DEBUG(INFO, "entry now 0x%x end 0x%x\n", _entryOffset, _nodeHeader->relOffsetEndUsed);
    }
  }
  return _entryOffset;
}
uint32_t		AttributeIndexAllocation::readNextIndex()
{
  DirectoryIndexEntry	*indexEntry;
  AttributeFileName_t	*attributeFileName;
  std::ostringstream	filename;
  uint32_t		i;
  uint8_t		*name;
  uint32_t		mftEntry;

  if (_entryOffset == 0) {
    _entryOffset = ATTRIBUTE_IA_SIZE + _nodeHeader->relOffsetStart;
  }

  DEBUG(INFO, "relOffsetEndUsed 0x%x\n", _nodeHeader->relOffsetEndUsed);
  DEBUG(INFO, "relOffsetEndAlloc 0x%x\n", _nodeHeader->relOffsetEndAlloc);
  DEBUG(INFO, "flags 0x%x\n\n", _nodeHeader->flags);

  if (_entryOffset >= _nodeHeader->relOffsetEndUsed || _entryOffset >= _indexRecordSize) {
    return 0;
  }

  indexEntry = (DirectoryIndexEntry *)(_contentBuffer + _entryOffset);
  if (indexEntry->entryLength == 0) {
    return 0;
  }
#if __WORDSIZE == 64
  mftEntry = indexEntry->fileNameMFTFileReference & 0xffffffUL;
#else
  mftEntry = indexEntry->fileNameMFTFileReference & 0xffffffULL;
#endif
  DEBUG(INFO, "mftEntry: 0x%x (%u)\n", mftEntry, mftEntry);
  DEBUG(INFO, "currentOffset: 0x%x\n", _entryOffset);
  DEBUG(INFO, " entryLength: 0x%x\n", indexEntry->entryLength);
  DEBUG(INFO, " fileNameLength: 0x%x\n", indexEntry->fileNameLength);
  if (indexEntry->flags & ENTRY_CHILD_NODE_EXIST) {
    DEBUG(INFO, " Has child\n");
    ;
  }
  if (indexEntry->flags & ENTRY_LAST_ONE) {
    ;
    DEBUG(INFO, " Is the last entry\n");
  }
  
  filename.str("");
  attributeFileName = (AttributeFileName_t *)(_contentBuffer + _entryOffset +
					      DIRECTORY_INDEX_ENTRY_SIZE);
  
  DEBUG(INFO, " attributeFileNameLength: 0x%x\n", attributeFileName->nameLength);
#if __WORDSIZE == 64
  DEBUG(INFO, " nameoffset: 0x%lx\n", _realOffset + _entryOffset + DIRECTORY_INDEX_ENTRY_SIZE + ATTRIBUTE_FN_SIZE);
#else
  DEBUG(INFO, " nameoffset: 0x%llx\n", _realOffset + _entryOffset + DIRECTORY_INDEX_ENTRY_SIZE + ATTRIBUTE_FN_SIZE);
#endif
  name = (_contentBuffer + _entryOffset + DIRECTORY_INDEX_ENTRY_SIZE +
	  ATTRIBUTE_FN_SIZE + 8);
  for (i = 0; i < 100; i++) {
    if (!(i % 2)) {
      if (name[i] >= 0x20 && name[i] <= 0x7e) {
	filename << name[i];
      }
      if (name[i] == 0)
	break;
    }
  }
  
#if __WORDSIZE == 64
  DEBUG(INFO, " parent fileref: 0x%.16lx\n", attributeFileName->parentDirectoryFileReference);
  DEBUG(INFO, " seqNumber: 0x%.16lx,  mftEntry:  0x%.16lx\n", (attributeFileName->parentDirectoryFileReference & 0xffff000000000000UL) >> 0x30, attributeFileName->parentDirectoryFileReference & 0x0000ffffffffffffUL);
  DEBUG(INFO, " realSizeOfFile: 0x%lx\n", attributeFileName->realSizeOfFile);
#else
  DEBUG(INFO, " parent fileref: 0x%.16llx\n", attributeFileName->parentDirectoryFileReference);
  DEBUG(INFO, " seqNumber: 0x%.16llx,  mftEntry:  0x%.16llx\n", (attributeFileName->parentDirectoryFileReference & 0xffff000000000000ULL) >> 0x30, attributeFileName->parentDirectoryFileReference & 0x0000ffffffffffffULL);
  DEBUG(INFO, " realSizeOfFile: 0x%llx\n", attributeFileName->realSizeOfFile);
#endif
  DEBUG(INFO, " length1: %u\n", indexEntry->fileNameLength);
  DEBUG(INFO, " length2: %u\n", attributeFileName->nameLength);
  DEBUG(INFO, " length3: %u\n", indexEntry->entryLength);
  DEBUG(INFO, " filename: %s\n", filename.str().c_str());
  DEBUG(INFO, " flags: 0x%x\n", attributeFileName->flags);
  
  DEBUG(INFO, "current 0x%x end 0x%x mft# %u entryLength %u\n", _entryOffset, _nodeHeader->relOffsetEndUsed, mftEntry, indexEntry->entryLength);
  _entryOffset += indexEntry->entryLength;
  return mftEntry;
}

void		AttributeIndexAllocation::content()
{
  uint64_t	currentOffset;

  while ((currentOffset = nextOffset())) {
    //    currentOffset *= 1024;
#if __WORDSIZE == 64
    printf("currentOffset indexAllocation: 0x%lx\n", currentOffset);
#else
    printf("currentOffset indexAllocation: 0x%llx\n", currentOffset);
#endif
  }
}

void		AttributeIndexAllocation::dumpHeader()
{
  DEBUG(INFO, "Index allocation record header:\n\tsignature %c%c%c%c\n", _data->signature[0],  _data->signature[1], _data->signature[2],  _data->signature[3]);
  DEBUG(INFO, "\tfixupArrayOffset 0x%x\n", _data->fixupArrayOffset);
  DEBUG(INFO, "\tfixupAmount 0x%x\n", _data->fixupAmount);
#if __WORDSIZE == 64
  DEBUG(INFO, "\tsequenceNumber 0x%lx\n", _data->sequenceNumber);
  DEBUG(INFO, "\trecordVCN 0x%lx\n", _data->recordVCN);
#else
  DEBUG(INFO, "\tsequenceNumber 0x%llx\n", _data->sequenceNumber);
  DEBUG(INFO, "\trecordVCN 0x%llx\n", _data->recordVCN);
#endif
}

void		AttributeIndexAllocation::dumpNodeHeader()
{
  printf("Node header:\n");
  printf("\trelOffsetStart: 0x%x\n", _nodeHeader->relOffsetStart);
  printf("\trelOffsetEndUsed: 0x%x\n", _nodeHeader->relOffsetEndUsed);
  printf("\trelOffsetEndAlloc: 0x%x\n", _nodeHeader->relOffsetEndAlloc);
  printf("\tflags: 0x%x\n", _nodeHeader->flags);
}

void			AttributeIndexAllocation::dumpEntries()
{
  DirectoryIndexEntry	*current;
  AttributeFileName_t	*attrFileName;
  std::ostringstream	filename;
  uint32_t		i;
  uint8_t		*name;

  _bufferOffset = 0;

  while (_entryOffset < _indexRecordSize) {
    current = (DirectoryIndexEntry *)(_contentBuffer + _entryOffset);
    printf("Entry at offset 0x%x\n", _entryOffset);
    if (current->fileNameMFTFileReference & 0xffffffUL) {
#if __WORDSIZE == 64
      printf("\tmftEntry %lu\n", current->fileNameMFTFileReference & 0xffffffUL);
#else
      printf("\tmftEntry %llu\n", current->fileNameMFTFileReference & 0xffffffUL);
#endif
    }
    printf("\tentryLength 0x%x\n", current->entryLength);
    printf("\tfileNameLength 0x%x\n", current->fileNameLength);

    filename.str("");
    attrFileName = (AttributeFileName_t *)(_contentBuffer + _entryOffset + DIRECTORY_INDEX_ENTRY_SIZE);
    printf("\tFilename attribute:\n");
    printf("\t\tattributeFileNameLength: 0x%x\n", attrFileName->nameLength);
    name = (_contentBuffer + _entryOffset + DIRECTORY_INDEX_ENTRY_SIZE + ATTRIBUTE_FN_SIZE);
    for (i = 0; i < (uint32_t)(attrFileName->nameLength * 2); i++) {
      if (!(i % 2)) {
	//	if (name[i] >= 0x20 && name[i] <= 0x7e) {
	  filename << name[i];
	  //	}
	  //	if (name[i] == 0)
	  //	  break;
      }
    }
    
#if __WORDSIZE == 64
    printf("\t\tparent fileref: 0x%.16lx\n", attrFileName->parentDirectoryFileReference);
    printf("\t\t\tseqNumber: 0x%.16lx,  mftEntry:  %lu (0x%.16lx)\n", (attrFileName->parentDirectoryFileReference & 0xffff000000000000UL) >> 0x30, attrFileName->parentDirectoryFileReference & 0x0000ffffffffffffUL, attrFileName->parentDirectoryFileReference & 0x0000ffffffffffffUL);
    printf("\t\trealSizeOfFile: %lu (0x%lx\n)", attrFileName->realSizeOfFile, attrFileName->realSizeOfFile);
#else
    printf("\t\tparent fileref: 0x%.16llx\n", attrFileName->parentDirectoryFileReference);
    printf("\t\t\tseqNumber: 0x%.16llx,  mftEntry:  0x%.16llx\n", (attrFileName->parentDirectoryFileReference & 0xffff000000000000ULL) >> 0x30, attrFileName->parentDirectoryFileReference & 0x0000ffffffffffffULL);
    printf("\t\trealSizeOfFile: 0x%llx\n", attrFileName->realSizeOfFile);
#endif
    printf("\t\tfilename: %s\n", filename.str().c_str());
    printf("\t\tflags: 0x%x\n", attrFileName->flags);
    
    if (current->flags & ENTRY_CHILD_NODE_EXIST) {
      printf("\t\t Has child\n");
    }
    if (current->flags & ENTRY_LAST_ONE) {
      printf("\t\t Is the last entry\n");
      break;
    }

    _entryOffset += current->entryLength;
  }
}
