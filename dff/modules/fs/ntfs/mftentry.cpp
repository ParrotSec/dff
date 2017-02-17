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

#include <sstream>

#include "vfile.hpp"
#include "mftentry.hpp"

MftEntry::MftEntry(VFile *vfile)
{
  _vfile = vfile;
  _mftEntryBlock = new MftEntryBlock;
  _bufferOffset = 0;
  _previousReadOffset = 0;
  _clusterSize = 0;
  _mftEntrySize = 0;
  _attributeOffset = 0;
  _indexRecordSize = 0;
  _sectorSize = 0;
  _currentAttribute = new Attribute(_vfile);
  _readBuffer = NULL;
  _fixupValues = NULL;
  _fixupSignature = 0;
  _attributeHeader = NULL;
}

//XXX fix sometime it's deleted but fd of vfile is already used elsewhere so it must not close it, and some time it's not used so it must be closed
void MftEntry::close()
{
  _vfile->close();
}

MftEntry::~MftEntry()
{
//	_vfile->close();
  delete _currentAttribute;
  if (_fixupValues != NULL) {
    delete _fixupValues;
  }
}

MftEntryBlock	*MftEntry::getMftEntryBlock()
{
  return _mftEntryBlock;
}

void	MftEntry::clusterSize(uint16_t size)
{
  _clusterSize = size;
  DEBUG(INFO, "cs: 0x%x\n", size);
  _currentAttribute->clusterSize(size);
}

void	MftEntry::mftEntrySize(uint16_t size)
{
  _mftEntrySize = size;
  _readBuffer = new uint8_t[size];
  _currentAttribute->mftEntrySize(size);
}


void	MftEntry::indexRecordSize(uint16_t size)
{
  _indexRecordSize = size;
  _currentAttribute->indexRecordSize(size);
}

void	MftEntry::sectorSize(uint16_t size)
{
  _sectorSize = size;
  _currentAttribute->sectorSize(size);
}


void		MftEntry::dumpHeader()
{
  uint8_t	i;

#if __WORDSIZE == 64
  DEBUG(CRITICAL, "MftEntry at offset 0x%lx\n", _previousReadOffset);
#else
  DEBUG(CRITICAL, "MftEntry at offset 0x%llx\n", _previousReadOffset);
#endif
  DEBUG(CRITICAL, "\tfixupArrayOffset 0x%x\n", _mftEntryBlock->fixupArrayOffset);
  DEBUG(CRITICAL, "\tfixupNumber 0x%x\n", _mftEntryBlock->fixupNumber);
  DEBUG(CRITICAL, "\tsequenceValue 0x%x\n", _mftEntryBlock->sequenceValue);
  DEBUG(CRITICAL, "\tlinkCount 0x%x\n", _mftEntryBlock->linkCount);
  DEBUG(CRITICAL, "\tfirstAttributeOffset 0x%x\n", _mftEntryBlock->firstAttributeOffset);
  DEBUG(CRITICAL, "\tflag 0x%x\n", _mftEntryBlock->flag);
  DEBUG(CRITICAL, "\tusedSizeMftEntry 0x%x\n", _mftEntryBlock->usedSizeMftEntry);
  DEBUG(CRITICAL, "\tallocatedSizeMftEntry 0x%x\n", _mftEntryBlock->allocatedSizeMftEntry);
#if __WORDSIZE == 64
  DEBUG(CRITICAL, "\tlogFileLSN 0x%lx\n", _mftEntryBlock->logFileLSN);
  DEBUG(CRITICAL, "\tfileReferenceToBaseRecord %ld\n", _mftEntryBlock->fileReferenceToBaseRecord);
#else
  DEBUG(CRITICAL, "\tlogFileLSN 0x%llx\n", _mftEntryBlock->logFileLSN);
  DEBUG(CRITICAL, "\tfileReferenceToBaseRecord %lld\n", _mftEntryBlock->fileReferenceToBaseRecord);
#endif
  DEBUG(CRITICAL, "\tnextAttributeId 0x%x\n", _mftEntryBlock->nextAttributeId);
  DEBUG(CRITICAL, "\tEntry have fixup:\n");
  DEBUG(CRITICAL, "\tSignature 0x%.4x\n", _fixupSignature);
  for (i = 0; i < _mftEntryBlock->fixupNumber - 1; i++) {
    DEBUG(CRITICAL, "\t\tValue to replace #%u 0x%.4x\n", i, _fixupValues[i]);
    ;
  }

  //  _fixFixup();
}

/**
 * Read in _vfile, based on a cluster size
 *  TODO
 *   once sector fixup values are known, we must replace it in _readBuffer
 */
void	MftEntry::_bufferedRead(uint64_t offset)
{
#if __WORDSIZE == 64
  DEBUG(INFO, "requesting read to 0x%lx with size 0x%x\n", offset, _mftEntrySize);
#else
  DEBUG(INFO, "requesting read to 0x%llx with size 0x%x\n", offset, _mftEntrySize);
#endif
  if (offset - _previousReadOffset >= _mftEntrySize ||
      (offset == 0 && _previousReadOffset == 0)) {

    if (_readBuffer == NULL && _mftEntrySize > 0) {
      _readBuffer = new uint8_t[_mftEntrySize];
    }

    memset(_readBuffer, 0, _mftEntrySize);
    _vfile->seek(offset);
    _vfile->read(_readBuffer, _mftEntrySize);
    _previousReadOffset = offset;
    _mftEntryBlock = (MftEntryBlock *)_readBuffer;
    _bufferOffset = 0;
    _entryOffset = 0;
#if __WORDSIZE == 64
    DEBUG(INFO, "NEAD to read @ 0x%lx previous read offset: 0x%lx buffOffset: 0x%x\n", offset, _previousReadOffset, _bufferOffset);
#else
    DEBUG(INFO, "NEAD to read @ 0x%llx previous read offset: 0x%llx buffOffset: 0x%x\n", offset, _previousReadOffset, _bufferOffset);
#endif
  }
  else {
    _bufferOffset = offset - _previousReadOffset;
    _mftEntryBlock = (MftEntryBlock *)(_readBuffer + _bufferOffset);
    _entryOffset = _bufferOffset;
    DEBUG(INFO, "NO nead to read bufferOffset is now 0x%x\n", _bufferOffset);
    DEBUG(INFO, "fiiiixup number 0x%x\n", _mftEntryBlock->fixupNumber);
  }

  //  _fixFixup();
}

void	MftEntry::_bufferedRead(uint64_t offset, uint32_t size)
{
#if __WORDSIZE == 64
  DEBUG(INFO, "requesting read to 0x%lx with size 0x%x\n", offset, size);
#else
  DEBUG(INFO, "requesting read to 0x%llx with size 0x%x\n", offset, size);
#endif
  if (_readBuffer != NULL) {
    delete _readBuffer;
  }

  _readBuffer = new uint8_t[size];

  if (offset - _previousReadOffset >= size ||
      (offset == 0 && _previousReadOffset == 0)) {
    memset(_readBuffer, 0, size);
    _vfile->seek(offset);
    _vfile->read(_readBuffer, size);
    _previousReadOffset = offset;
    _mftEntryBlock = (MftEntryBlock *)_readBuffer;
    _bufferOffset = 0;
    _entryOffset = 0;
#if __WORDSIZE == 64
    DEBUG(INFO, "NEAD to read @ 0x%lx previous read offset: 0x%lx\n", offset, _previousReadOffset);
#else
    DEBUG(INFO, "NEAD to read @ 0x%llx previous read offset: 0x%llx\n", offset, _previousReadOffset);
#endif
  }
  else {
    _bufferOffset = offset - _previousReadOffset;
    _mftEntryBlock = (MftEntryBlock *)(_readBuffer + _bufferOffset);
    _entryOffset = _bufferOffset;
    DEBUG(INFO, "NO nead to read bufferOffset is now 0x%x\n", _bufferOffset);
    DEBUG(INFO, "fiiiixup number 0x%x\n", _mftEntryBlock->fixupNumber);
  }

  //  _fixFixup();
}

bool			MftEntry::_validateSignature()
{
  std::ostringstream	expectedSignature;
  uint8_t		i;

  _previousReadOffset = 0;
  expectedSignature << MFTENTRY_SIGNATURE;

  if (_mftEntryBlock == NULL)
    return false;

  if (_mftEntryBlock->signature == NULL)
    return false;

  for (i = 0; i < expectedSignature.str().size(); i++)
    {
      /* Char by char because no trailing \0 at end of signature */
      if (expectedSignature.str()[i] != _mftEntryBlock->signature[i])
	{
	  DEBUG(INFO, "No valid MFTEntry entry found got '%c' expected '%c'\n", _mftEntryBlock->signature[i], expectedSignature.str()[i]);
	  return false;
	}
    }
  return true;
}

bool			MftEntry::isMftEntryBlock(uint64_t offset)
{
#if __WORDSIZE == 64
  DEBUG(INFO, "Seek to 0x%lx\n", offset);
#else
  DEBUG(INFO, "Seek to 0x%llx\n", offset);
#endif
  /* Direct read amount of data needed in _vfile to validate if we are at the
   * begining of an MFT entry */
  _vfile->seek(offset);
  _vfile->read(_mftEntryBlock, MFTENTRY_HEADER_SIZE);
  
  /* Validate MFT Signature */
  return _validateSignature();
}

/**
 * Like isMftEntryBlock but read more data to decode content
 *  and set offset
 */
bool		MftEntry::decode(uint64_t offset)
{
  uint8_t	i;
  uint8_t	lbreak = 0;

#if __WORDSIZE == 64
  DEBUG(INFO, "Reading 0x%lx\n", offset);
#else
  DEBUG(INFO, "Reading 0x%llx\n", offset);
#endif
  /* Read from previous buffer or read again in _vfile */
  _bufferedRead(offset);

  /* Validate MFT Signature */
#if __WORDSIZE == 64
  DEBUG(INFO, "reading at 0x%lx\n", offset);
#else
  DEBUG(INFO, "reading at 0x%llx\n", offset);
#endif
  if (!_validateSignature()) {
    DEBUG(INFO, "sign not valid\n");
    return false;
  }

  /* Set fixup values */
  if (_mftEntryBlock->fixupNumber > 0) {
    i = 0;
    _fixupValues = new uint16_t[_mftEntryBlock->fixupNumber];
    _bufferOffset += _mftEntryBlock->fixupArrayOffset;
    _fixupSignature = (uint16_t)(*(uint16_t *)(_readBuffer + _bufferOffset));
    DEBUG(VERBOSE, "fixup signature: 0x%.4x buffOffset: 0x%x\n", _fixupSignature, _bufferOffset);
    _bufferOffset += SIZE_2BYTES;
    while (i < _mftEntryBlock->fixupNumber) {
      _fixupValues[i] = (uint16_t)(*(uint16_t *)(_readBuffer + _bufferOffset));
      DEBUG(VERBOSE, "fixup value found: 0x%.4x buffOffset: 0x%x\n", _fixupValues[i], _bufferOffset);
      _bufferOffset += SIZE_2BYTES;
      i++;
    }
  }
  DEBUG(VERBOSE, "mft sign: %s\n", _mftEntryBlock->signature);
  DEBUG(VERBOSE, "fixup offset: 0x%x\n", _mftEntryBlock->fixupArrayOffset);
  DEBUG(VERBOSE, "fixup number of fixup: 0x%x\n", _mftEntryBlock->fixupNumber);
#if __WORDSIZE == 64
  DEBUG(INFO, "lsn: 0x%lx\n", _mftEntryBlock->logFileLSN);
#else
  DEBUG(INFO, "lsn: 0x%llx\n", _mftEntryBlock->logFileLSN);
#endif

  /*
_attributeOffset = _mftEntryBlock->fixupArrayOffset +
    (_mftEntryBlock->fixupNumber + 1) * SIZE_2BYTES;
  */
  _attributeOffset = _mftEntryBlock->firstAttributeOffset;
  _bufferOffset = _mftEntryBlock->firstAttributeOffset;

  /* fixup */
  i = 0;
  lbreak = 0;
  while (_mftEntryBlock->fixupNumber && i < _mftEntryBlock->fixupNumber - 1) {
    DEBUG(VERBOSE, "jumping to 0x%x\n", _entryOffset + ((i + 1) * _sectorSize) - 2);
    uint16_t	*valToFix = (uint16_t *)(_readBuffer + _entryOffset + ((i + 1) * _sectorSize) - 2);
    DEBUG(VERBOSE, "fixup Got: 0x%.4x\n", *valToFix);
    *valToFix = (uint16_t)(_fixupValues[i]);
    DEBUG(VERBOSE, "fixup Wrote: 0x%.4x\n", *valToFix);
    i++;
    if (lbreak++ == 255)
      break;  
  }

  return true;
}

void		MftEntry::_fixFixup()
{
  uint16_t	*valToFix = (uint16_t *)(_readBuffer + _bufferOffset + _sectorSize - 2);

  DEBUG(INFO, "=== FIXUP VALIDATION AND CLEANING ===\n");
  DEBUG(INFO, "\tSector size is 0x%x\n", _sectorSize);
  DEBUG(INFO, "\tFixup signature is 0x%.4x\n", _fixupSignature);
  DEBUG(INFO, "\tValue1 to fix: 0x%.4x\n", *valToFix);
  *valToFix = _fixupValues[0];
  DEBUG(INFO, "\tFixed to 0x%.4x\n", *valToFix);
  valToFix = (uint16_t *)(_readBuffer + _bufferOffset + (_sectorSize * 2) - 2);
  DEBUG(INFO, "\tValue2 to fix: 0x%.4x\n", *valToFix);
  *valToFix = _fixupValues[1];
  DEBUG(INFO, "\tFixed to 0x%.4x\n", *valToFix);
  DEBUG(INFO, "\tFixed to 0x%.4x\n", *((uint16_t *)(_readBuffer + _bufferOffset + _sectorSize - 2)));

}

Attribute	*MftEntry::getNextAttribute()
{
  if ((_attributeOffset + ATTRIBUTE_HEADER_SIZE) >=
      _mftEntryBlock->usedSizeMftEntry) {
    if (_readBuffer != NULL) {
      delete _readBuffer;
      _readBuffer = NULL;
    }
    return NULL;
  }

  if (*(uint32_t *)(_readBuffer + _bufferOffset) == ATTRIBUTE_END) {
    if (_readBuffer != NULL) {
      delete _readBuffer;
      _readBuffer = NULL;
    }
    return NULL;
  }
  _attributeHeader = (AttributeHeader *)(_readBuffer + _bufferOffset);

  _currentAttribute->setOrigin(_attributeHeader, _readBuffer, _bufferOffset,
			       _attributeOffset);
  _bufferOffset += _attributeHeader->attributeLength;
  _attributeOffset += _attributeHeader->attributeLength;

  if (_mftEntryBlock->fixupNumber > 0) {
    uint8_t	i;

    _currentAttribute->fixupOffsets(_mftEntryBlock->fixupNumber);
    for(i = 0; i < _mftEntryBlock->fixupNumber; i++)
      _currentAttribute->fixupOffset(i, _previousReadOffset + _entryOffset +
				     _mftEntryBlock->fixupArrayOffset +
				     (i + 1) * SIZE_2BYTES);
  }

  DEBUG(INFO, "\tattr @ 0x%x, type: 0x%x: %s, non resident: 0x%x, attribute length: 0x%x\n", _attributeOffset - _attributeHeader->attributeLength, _attributeHeader->attributeTypeIdentifier, _currentAttribute->getName(_attributeHeader->attributeTypeIdentifier).c_str(), _attributeHeader->nonResidentFlag, _attributeHeader->attributeLength);
  return _currentAttribute;
}

void	MftEntry::dumpAttribute(Attribute *attribute)
{
  if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_STANDARD_INFORMATION) {
    AttributeStandardInformation	*metaStandardInformation = new AttributeStandardInformation(*attribute);

    metaStandardInformation->content();
  }
  else if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_ATTRIBUTE_LIST) {
    AttributeAttributeList	*metaAttributeList = new AttributeAttributeList(_vfile, *attribute);

    metaAttributeList->content();
  }
  else if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_FILE_NAME) {
    AttributeFileName	*metaFileName = new AttributeFileName(*attribute);
    
    metaFileName->content();
  }
  else if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_VOLUME_VERSION_OR_OBJECT_ID) {
    //_attributeObjectID();
    ;
  }
  else if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_SECURITY_DESCRIPTOR) {
    //_attributeSecurityDescriptor();
    ;
  }
  else if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_VOLUME_NAME) {
    //_attributeVolumeName();
    ;
  }
  else if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_VOLUME_INFORMATION) {
    //_attributeVolumeInformation();
    ;
  }
  else if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_DATA) {
    AttributeData	*data = new AttributeData(*attribute);

    if (attribute->attributeHeader()->nonResidentFlag) {
      dumpChunks(data->offsetsRuns(), data->getRunListSize());
    }
    else {
      data->content();
    }
  }
  else if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_INDEX_ROOT) {
    AttributeIndexRoot	*metaIndexRoot = new AttributeIndexRoot(*attribute);

    metaIndexRoot->content();
  }
  else if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_INDEX_ALLOCATION) {
    // TODO should not exist without an INDEX_ROOT attribute, check it
    //   also check signature is INDX for carving
    AttributeIndexAllocation	*data = new AttributeIndexAllocation(*attribute);

    if (attribute->attributeHeader()->nonResidentFlag) {
      dumpChunks(data->offsetsRuns(), data->getRunListSize());
    }
    else {
      data->content();
    }
  }
  else if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_BITMAP) {
    AttributeBitmap	*data = new AttributeBitmap(*attribute);

    if (attribute->attributeHeader()->nonResidentFlag) {
      dumpChunks(data->offsetsRuns(), data->getRunListSize());
    }
    else {
      data->content();
    }
  }
  else if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_SYMBOLINC_LINK_OR_REPARSE_POINT) {
    AttributeReparsePoint	*metaReparsePoint = new AttributeReparsePoint(*attribute);

    metaReparsePoint->content();
  }
  else if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_EA_INFORMATION) {
    //_attributeEAInformation();
    ;
  }
  else if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_EA) {
    //_attributeEA();
    ;
  }
  else if (_attributeHeader->attributeTypeIdentifier == ATTRIBUTE_LOGGED_UTILITY_STREAM) {
    //_attributeLoggedUtilityStream();
    ;
  }

  DEBUG(INFO, "\n");
}

uint16_t	MftEntry::_runList(uint16_t runDescOffset)
{
  uint8_t	*runList = (_readBuffer + runDescOffset);
  uint8_t	runLengthSize;
  uint8_t	runOffsetSize;
  uint64_t	runLength = 0;
  uint64_t	runOffset = 0; // Offset is signed, relative to previous offset
  uint16_t	index;

  DEBUG(INFO, "\t\tAttribute DATA in 0x%x\n", runDescOffset);
  runLengthSize = runList[0] & 0xF;
  runOffsetSize = runList[0] >> 4;
  DEBUG(INFO, "\t\t\trunLenghtSize: 0x%x\n", runLengthSize);
  if (runLengthSize == 0) {
    DEBUG(INFO, "\t\t\tover\n");
    return 0;
  }
  DEBUG(INFO, "\t\t\trunOffsetSize: 0x%x\n", runOffsetSize);

  // Read run length byte per byte
  for (index = 0; index < runLengthSize; index++)
    runLength += ((uint64_t)*((uint8_t *)(runList + (index + 1) * SIZE_BYTE)))
      << (index * BITS_IN_BYTE);

  // Read run offset byte per byte
  //  FIXME offset is signed, because it is relative to previous offset
  for (index = 0; index < runOffsetSize; index++) {
    runOffset += ((uint64_t)*((uint8_t *)(runList + runLengthSize +
					  (index + 1) * SIZE_BYTE)))
      << (index * BITS_IN_BYTE);
  }

#if __WORDSIZE == 64
  DEBUG(INFO, "\t\t\trunLength: 0x%.16lx\n", runLength);
  DEBUG(INFO, "\t\t\trunOffset: 0x%.16lx (from %lu to %lu)\n", runOffset + _previousRunOffset, runOffset + _previousRunOffset, runOffset + _previousRunOffset + runLength - 1);
#else
  DEBUG(INFO, "\t\t\trunLength: 0x%.16llx\n", runLength);
  DEBUG(INFO, "\t\t\trunOffset: 0x%.16llx (from %llu to %llu)\n", runOffset + _previousRunOffset, runOffset + _previousRunOffset, runOffset + _previousRunOffset + runLength - 1);
#endif
  _previousRunOffset = runOffset + _previousRunOffset;

  return runDescOffset + SIZE_BYTE + runLengthSize + runOffsetSize;
}

uint16_t		MftEntry::discoverMftEntrySize(uint64_t offset)
{
  uint16_t		mftEntrySize = 512; // Start at the minimum, size of a sector..
  uint8_t		i = 0;

  _bufferedRead(offset, 8192);

  while (mftEntrySize && i != 4 && (mftEntrySize <( 8192 - 4))) { 
    if ((uint32_t)*(_readBuffer + mftEntrySize) != (uint32_t)*MFTENTRY_SIGNATURE)
	    mftEntrySize *= 2;
    else
    {
      DEBUG(INFO, "MftEntrySize of %u bytes found valid\n", mftEntrySize);
      DEBUG(INFO, "return  %u\n", mftEntrySize);
      _readBuffer = new uint8_t[mftEntrySize];
      return mftEntrySize;
    }
 }
  return 0;
}

void	MftEntry::dumpChunks(OffsetRun *offsets, uint16_t runListSize) {
  uint16_t	runListIndex = 0;
  uint32_t	prevLength = 0;
  int64_t	prevOffset = 0;
  OffsetRun	*offset;

  printf("\t\t\tChunks amount: %u\n", runListSize);
  while (runListIndex < runListSize) {
    offset = &(offsets[runListIndex]);
    printf("\t\t\t\tChunk #%u\tlength %u (0x%x)\n", runListIndex + 1, offset->runLength - prevLength, offset->runLength - prevLength);
#if __WORDSIZE == 64
    if (offset->runLength - prevLength > 1) {
      printf("\t\t\t\t\t\tcluster %lu (0x%lx) to %lu (0x%lx)\n", offset->runOffset, offset->runOffset, offset->runOffset + (offset->runLength - prevLength) - 1, offset->runOffset + (offset->runLength - prevLength) - 1);
    }
    else {
      printf("\t\t\t\t\t\tcluster %lu (0x%lx)\n", offset->runOffset, offset->runOffset);
    }
    if (prevOffset) {
      printf("\t\t\t\t\t\trelative from previous %li (0x%lx)\n", offset->runOffset - prevOffset, offset->runOffset - prevOffset);
    }
#else
    if (offset->runLength - prevLength > 1) {
      printf("\t\t\t\t\t\tcluster %llu (0x%llx) to %llu (0x%llx)\n", offset->runOffset, offset->runOffset, offset->runOffset + (offset->runLength - prevLength) - 1, offset->runOffset + (offset->runLength - prevLength) - 1);
    }
    else {
      printf("\t\t\t\t\t\tcluster %llu (0x%llx)\n", offset->runOffset, offset->runOffset);
    }
    if (prevOffset) {
      printf("\t\t\t\t\t\trelative from previous %lli (0x%llx)\n", prevOffset - offset->runOffset, prevOffset - offset->runOffset);
    }
#endif
    prevLength = offset->runLength;
    prevOffset = offset->runOffset;
    runListIndex++;
  }
}

void	MftEntry::continueAt(uint16_t bufferOffset, uint16_t attributeOffset)
{
  _bufferOffset = bufferOffset;
  _attributeOffset = attributeOffset;
}
