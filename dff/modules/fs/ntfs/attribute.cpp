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
#include "attribute.hpp"


Attribute::Attribute(VFile *vfile)
{
  _vfile = vfile;
  _offsetListSize = 0;
  _parentMftOffset = 0;
  _mftIndex = 0;

  _baseOffset = 0;
  _attributeRealOffset = 0;
  _mftEntrySize = 0;
  _indexRecordSize = 0;
  _sectorSize = 0;
  _clusterSize = 0;
  _currentRunIndex = 0;
  _fixupIndexes = NULL;
  _runAmount = 0;
}

Attribute::~Attribute()
{
  ;
}

void	Attribute::setOrigin(AttributeHeader *header, uint8_t *readBuffer,
			     uint16_t bufferOffset,
			     uint16_t attributeOffset)
{
  _attributeHeader = header;
  if (!_parentMftOffset)
    _parentMftOffset = bufferOffset;
  _bufferOffset = bufferOffset;
  _attributeOffset = attributeOffset;
  _readBuffer = readBuffer;
}

uint16_t	Attribute::getType()
{
  return _attributeHeader->attributeTypeIdentifier;
}

void	Attribute::content()
{
  ;
}

void	Attribute::readHeader()
{
  _attributeHeader = (AttributeHeader *)(_readBuffer + _bufferOffset);

  if (_attributeHeader->nonResidentFlag) {
    _attributeNonResidentDataHeader = (AttributeNonResidentDataHeader *)
      (_readBuffer + _bufferOffset + ATTRIBUTE_HEADER_SIZE);
    _attributeResidentDataHeader = NULL;
  }
  else {
    _attributeNonResidentDataHeader = NULL;
    _attributeResidentDataHeader = (AttributeResidentDataHeader *)
      (_readBuffer + _bufferOffset + ATTRIBUTE_HEADER_SIZE);
  }

  _parentMftOffset = _bufferOffset - _attributeOffset;
  //_bufferOffset += _attributeHeader->attributeLength;
  //_attributeOffset += _attributeHeader->attributeLength;
}

void	Attribute::dumpHeader()
{
  printf("Attribute %s Header in 0x%x:\n", getFullName().c_str(), _attributeOffset);
  printf("\tattributeTypeIdentifier 0x%x\n", getType());
  printf("\tattributeLength 0x%x\n", _attributeHeader->attributeLength);
  printf("\tnonResidentFlag 0x%x\n", _attributeHeader->nonResidentFlag);
  printf("\tnameLength 0x%x\n", _attributeHeader->nameLength);
  printf("\tnameOffset 0x%x\n", _attributeHeader->nameOffset);
  printf("\tFlags 0x%x\n", _attributeHeader->flags);
  if (_attributeHeader->flags & ATTRIBUTE_FLAG_COMPRESSED) {
    printf("\t\tis compressed\n");
  }
  if (_attributeHeader->flags & ATTRIBUTE_FLAG_ENCRYPTED) {
    printf("\t\tis encrypted\n");
  }
  if (_attributeHeader->flags & ATTRIBUTE_FLAG_SPARSE) {
    printf("\t\tis sparse\n");
  }
  if (!(_attributeHeader->flags & ATTRIBUTE_FLAG_COMPRESSED)
      && !(_attributeHeader->flags & ATTRIBUTE_FLAG_ENCRYPTED)
      && !(_attributeHeader->flags & ATTRIBUTE_FLAG_SPARSE)) {
    printf("\t\tunknown\n");
  }

  printf("\tattributeIdentifier 0x%x\n", _attributeHeader->attributeIdentifier);
  if (_attributeHeader->nonResidentFlag) {
    printf("\tNon-resident data header:\n");
#if __WORDSIZE == 64
    printf("\t\tStarting VCN\t0x%.16lx\n", _attributeNonResidentDataHeader->startingVCN);
    printf("\t\tEnding VCN\t0x%.16lx\n", _attributeNonResidentDataHeader->endingVCN);
#else 
    printf("\t\tStarting VCN 0x%.16llx\n", _attributeNonResidentDataHeader->startingVCN);
    printf("\t\tEnding VCN 0x%.16llx\n", _attributeNonResidentDataHeader->endingVCN);
#endif
    printf("\t\tRun list offset 0x%x\n", _attributeNonResidentDataHeader->runListOffset);
    printf("\t\tCompression unit size 0x%x\n", _attributeNonResidentDataHeader->compressionUnitSize);
    printf("\t\tUnused 0x%x\n", _attributeNonResidentDataHeader->unused);
#if __WORDSIZE == 64
    printf("\t\tAttribute content allocated size\t%lu bytes\n", _attributeNonResidentDataHeader->attributeContentAllocatedSize);
    printf("\t\tAttribute content actual size\t\t%lu bytes\n", _attributeNonResidentDataHeader->attributeContentActualSize);
    printf("\t\tAttribute content initialized size\t%lu bytes\n", _attributeNonResidentDataHeader->attributeContentInitializedSize);
#else
    printf("\t\tAttribute content allocated size\t%llu bytes\n", _attributeNonResidentDataHeader->attributeContentAllocatedSize);
    printf("\t\tAttribute content actual size\t\t%llu bytes\n", _attributeNonResidentDataHeader->attributeContentActualSize);
    printf("\t\tAttribute content initialized size\t%llu bytes\n", _attributeNonResidentDataHeader->attributeContentInitializedSize);
#endif
  }
  else {
    printf("\tResident data header:\n");
    printf("\t\tContent size %u bytes (0x%x)\n", _attributeResidentDataHeader->contentSize, _attributeResidentDataHeader->contentSize);
    printf("\t\tContent offset 0x%x\n", _attributeResidentDataHeader->contentOffset);
    printf("Attribute Content:\n");    
  }
}

void		Attribute::setContent()
{
  if (_attributeHeader->nonResidentFlag) {
    setRunList();
    return ;
  }


}


/**
 * Specific to non resident attributes
 */
void		Attribute::setRunList()
{
  uint16_t	runListSize;
  uint16_t	runListIndex = 0;
  OffsetRun	*offsetRunToSet;
  uint16_t	runDescOffset = 0;

  runListSize = getRunListSize();
  _runAmount = 0;
  while (runListIndex < runListSize) {
    offsetRunToSet = getOffsetRun(runListIndex);

    runDescOffset = setNextRun(runDescOffset,
			       &(offsetRunToSet->runLength),
			       &(offsetRunToSet->runOffset));
    if (!_baseOffset) {
#if __WORDSIZE == 64
      DEBUG(INFO, "No base Offset, 0x%lx, 0x%x\n", offsetRunToSet->runOffset, _clusterSize);
#else
      DEBUG(INFO, "No base Offset, 0x%llx, 0x%x\n", offsetRunToSet->runOffset, _clusterSize);
#endif
      _baseOffset = offsetRunToSet->runOffset * _clusterSize;
    }

    //    _runAmount += _offsetList[runListIndex].runLength;
    _runAmount += offsetRunToSet->runLength;
    if (runListIndex) {
// Also transform relative offset addr to real addr
//  Be carefull ; runLength is relative to previous offset it can be signed !
      _offsetList[runListIndex].runLength += _offsetList[runListIndex - 1].runLength;
      _offsetList[runListIndex].runOffset += _offsetList[runListIndex - 1].runOffset;
    }
    runListIndex++;
  }

  runListIndex = 0;
}

uint16_t	Attribute::_runList(uint16_t runDescOffset)
{
  uint8_t	*runList = (_readBuffer + runDescOffset);
  uint8_t	runLengthSize;
  uint8_t	runOffsetSize;

  DEBUG(INFO, "\t\tRun list in 0x%x\n", runDescOffset);
  runLengthSize = runList[0] & 0xF;
  runOffsetSize = runList[0] >> 4;

  
  DEBUG(INFO, "\t\t\trunLenghtSize: 0x%x\n", runLengthSize);
  if (runLengthSize == 0) {
    DEBUG(INFO, "\t\t\tover\n");
    return 0;
  }
  DEBUG(INFO, "\t\t\trunOffsetSize: 0x%x\n", runOffsetSize);
  DEBUG(INFO, "\t\tNew desc offset: 0x%x\n", runDescOffset + SIZE_BYTE + runLengthSize + runOffsetSize);

  return runDescOffset + SIZE_BYTE + runLengthSize + runOffsetSize;
}

uint16_t	Attribute::getRunListSize()
{
  uint16_t	runDescOffset;
  uint16_t	items = 0;


  if (!(_attributeHeader->nonResidentFlag))
    // XXX
    return 0;

  if (_offsetListSize)
    return _offsetListSize;

  _previousRunOffset = 0;
  _attributeNonResidentDataHeader = (AttributeNonResidentDataHeader *)
    (_readBuffer + _bufferOffset + ATTRIBUTE_HEADER_SIZE);
  runDescOffset = _bufferOffset + _attributeNonResidentDataHeader->runListOffset;

  DEBUG(INFO, "offset: 0x%x versus 0x%x\n", runDescOffset, _bufferOffset + _attributeOffset + _attributeHeader->attributeLength);
  while ((runDescOffset = _runList(runDescOffset)) &&
	 runDescOffset < _bufferOffset + _attributeOffset +
	 _attributeHeader->attributeLength) {
    items++;
  }
  _offsetList = new OffsetRun[items];
  _offsetListSize = items;
  DEBUG(INFO, "offsetListSize: %u\n", _offsetListSize);

  return items;
}

OffsetRun	*Attribute::getOffsetRun(uint16_t index)
{
  return &(_offsetList[index]);
}

uint16_t	Attribute::getOffsetListSize()
{
  return _offsetListSize;
}

uint16_t	Attribute::setNextRun(uint16_t runDescOffset,
				      uint32_t *lengthPtr, int64_t *offsetPtr)
{
  uint8_t	*runList;
  uint8_t	runLengthSize;
  uint8_t	runOffsetSize;
  uint32_t	runLength = 0;
  int64_t	runOffset = 0; // Offset is signed, relative to previous offset
  uint16_t	index;
  bool		isSigned = false;
  int64_t	signConv = 0;
  uint8_t	value;

  if (!runDescOffset) {
    _previousRunOffset = 0;
    DEBUG(INFO, "bufferOffset: 0x%x\n", _bufferOffset);
    DEBUG(INFO, "runListOffset: 0x%x\n", _attributeNonResidentDataHeader->runListOffset);
    runDescOffset = _bufferOffset + _attributeNonResidentDataHeader->runListOffset;
  }
  runList = _readBuffer + runDescOffset;

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
    runLength += ((uint32_t)*((uint8_t *)(runList + (index + 1) * SIZE_BYTE)))
      << (index * BITS_IN_BYTE);

  // Read run offset byte per byte
  //  Be carreful ; offset is signed, because it is relative to previous offset
  if (runOffsetSize) {
    for (index = 0; index < runOffsetSize; index++) {
      value = *((uint8_t *)(runList + runLengthSize + (index + 1) * SIZE_BYTE));
      if (index == runOffsetSize - 1)
	if (value > 0x7f)
	  isSigned = true;
      runOffset += ((int64_t)value) << (index * BITS_IN_BYTE);
      signConv += 0xff << (index * BITS_IN_BYTE);
    }
    if (isSigned) {
      runOffset = -(signConv - runOffset + 1);
    }
  }
  else { // shadow node
#if __WORDSIZE == 64
    runOffset = 0x0UL;
#else
    runOffset = 0x0ULL;
#endif
  }

  DEBUG(INFO, "\t\t\trunLength: 0x%.8x\n", runLength);
#if __WORDSIZE == 64
  DEBUG(INFO, "\t\t\trunOffset: 0x%.16lx (relative: %li) (from %lu to %lu)\n", runOffset + _previousRunOffset, runOffset, runOffset + _previousRunOffset, runOffset + _previousRunOffset + runLength - 1);
#else
  DEBUG(INFO, "\t\t\trunOffset: 0x%.16llx (relative: %lli) (from %llu to %llu)\n", runOffset + _previousRunOffset, runOffset, runOffset + _previousRunOffset, runOffset + _previousRunOffset + runLength - 1);
#endif
  if (runOffsetSize)
    _previousRunOffset = runOffset + _previousRunOffset;
  *lengthPtr = runLength;
  *offsetPtr = runOffset;
  return runDescOffset + SIZE_BYTE + runLengthSize + runOffsetSize;
}

uint32_t	Attribute::idFromOffset(uint64_t offset)
{
  uint16_t	currentRunIndex = 0;
  uint16_t	offsetRunIndex = 0;
  uint32_t	offsetInRun = 0;
  uint32_t	i;
  uint8_t	mftIndex = 0;

  uint16_t	runLength;
  uint64_t	runOffset;

  for (i = 0; offsetRunIndex <= _offsetListSize; i++) {
    runLength = getOffsetRun(offsetRunIndex)->runLength;

    if (currentRunIndex >= runLength) {
      offsetRunIndex++;
      offsetInRun = 0;
      mftIndex = 0;
    }

    runOffset = (uint64_t)(getOffsetRun(offsetRunIndex)->runOffset * _clusterSize);
#if __WORDSIZE == 64
    DEBUG(CRITICAL, "id %u (0x%x) is @ 0x%lx\n", i, i, runOffset + (offsetInRun * _clusterSize) + (mftIndex * _mftEntrySize));
#else
    DEBUG(CRITICAL, "id %u (0x%x) is @ 0x%llx\n", i, i, runOffset + (offsetInRun * _clusterSize) + (mftIndex * _mftEntrySize));
#endif
    //    if (offset == (getOffsetRun(offsetRunIndex)->runOffset) * _clusterSize + (offsetInRun * _clusterSize) + (mftIndex * _mftEntrySize))
    if (offset == (runOffset + (offsetInRun * _clusterSize) + (mftIndex * _mftEntrySize)))
      {
	return i;
      }

    mftIndex++;
    if (mftIndex == _clusterSize / _mftEntrySize) {
      mftIndex = 0;
      offsetInRun++;
      currentRunIndex++;
    }
  }
  return 0;
}

uint64_t	Attribute::offsetFromID(uint32_t id)
{
  uint32_t	currentRunIndex = 0;
  uint16_t	offsetRunIndex = 0;
  uint32_t	offsetInRun = 0;
  uint32_t	i;
  uint32_t	mftIndex = 0;
  uint32_t	runLength;
  int64_t	runOffset;

  if (_mftEntrySize > _clusterSize) 
  {
    id *= (_mftEntrySize / _clusterSize);
  }

  runLength = getOffsetRun(0)->runLength;
  runOffset = getOffsetRun(0)->runOffset;
  //cout << "offsetRunIndex " << offsetRunIndex << " _offsetListSize " << _offsetListSize << endl;
  for (i = 0; offsetRunIndex <= _offsetListSize; i++) 
  {
    if (currentRunIndex >= runLength) 
    {
      offsetRunIndex++;
      offsetInRun = 0;
      mftIndex = 0;
      runLength = getOffsetRun(offsetRunIndex)->runLength;
      runOffset = getOffsetRun(offsetRunIndex)->runOffset;
    }
    //else
    //cout << "current run index " << currentRunIndex << " runLength " << runLength << endl;
    DEBUG(VERBOSE, "id is 0x%x we are searching for 0x%x\n", i, id);
    if (i == id) 
    {
#if __WORDSIZE == 64
      DEBUG(INFO, "id %u (0x%x) found @ 0x%lx\n", id, id, runOffset * _clusterSize + (offsetInRun * _clusterSize) + (mftIndex * _mftEntrySize));
#else
      DEBUG(INFO, "id %u (0x%x) found @ 0x%llx\n", id, id, runOffset * _clusterSize + (offsetInRun * _clusterSize) + (mftIndex * _mftEntrySize));
#endif
      return (runOffset * _clusterSize + offsetInRun * _clusterSize + 
	      mftIndex * _mftEntrySize);
    }
    if (_mftEntrySize < _clusterSize) 
    {
      mftIndex++;
      if (mftIndex == (uint16_t)(_clusterSize / _mftEntrySize)) 
      {
	mftIndex = 0;
	offsetInRun++;
	currentRunIndex++;
      }
    }
    else 
    {
      mftIndex = 0;
      offsetInRun++;
      currentRunIndex++;
    }
  }
  return 0;
}

uint64_t	Attribute::nextOffset()
{
#if __WORDSIZE == 64
  DEBUG(INFO, "current run %u offset in it 0x%lx run length %u\n", _currentRunIndex, getOffsetRun(_offsetRunIndex)->runOffset + _offsetInRun, getOffsetRun(_offsetRunIndex)->runLength);
#else
  DEBUG(INFO, "current run %u offset in it 0x%llx run length %u\n", _currentRunIndex, getOffsetRun(_offsetRunIndex)->runOffset + _offsetInRun, getOffsetRun(_offsetRunIndex)->runLength);
#endif
  if (_currentRunIndex >= getOffsetRun(_offsetRunIndex)->runLength) {
    _offsetInRun = 0;

    _offsetRunIndex++;
    if (_offsetRunIndex >= _offsetListSize) {
      _offsetInRun = 0;
      _offsetRunIndex = 0;
      return 0;
    }
  }

  if (_currentRunIndex++)
    return (getOffsetRun(_offsetRunIndex)->runOffset) * _clusterSize + (_offsetInRun++ * _clusterSize);
  else {
#if __WORDSIZE == 64
    DEBUG(INFO, "returning 0x%lx + (0x%x * 0x%x)\n", _baseOffset, _offsetInRun, _clusterSize);
#else
    DEBUG(INFO, "returning 0x%llx + (0x%x * 0x%x)\n", _baseOffset, _offsetInRun, _clusterSize);
#endif
    return _baseOffset + (_offsetInRun++ * _clusterSize); // + 0 first pass
  }
}

uint64_t	Attribute::nextMftOffset()
{
#if __WORDSIZE == 64
  DEBUG(INFO, "current run %u offset in it 0x%lx run length %u run index %u size of list %u\n", _currentRunIndex, getOffsetRun(_offsetRunIndex)->runOffset + _offsetInRun, getOffsetRun(_offsetRunIndex)->runLength, _offsetRunIndex, _offsetListSize);
#else
  DEBUG(INFO, "current run %u offset in it 0x%llx run length %u run index %u size of list %u\n", _currentRunIndex, getOffsetRun(_offsetRunIndex)->runOffset + _offsetInRun, getOffsetRun(_offsetRunIndex)->runLength, _offsetRunIndex, _offsetListSize);
#endif
  if (_currentRunIndex >= getOffsetRun(_offsetRunIndex)->runLength) {
    _offsetInRun = 0;
    _mftIndex = 0;

    _offsetRunIndex++;
    if (_offsetRunIndex >= _offsetListSize) {
      _offsetInRun = 0;
      _offsetRunIndex = 0;
      return 0;
    }
  }

  if (_currentRunIndex) {
    if (_mftIndex == _clusterSize / _mftEntrySize) {
      _mftIndex = 0;
      _currentRunIndex++;
      _offsetInRun++;
    }
    return (getOffsetRun(_offsetRunIndex)->runOffset) * _clusterSize + (_offsetInRun * _clusterSize) + (_mftIndex++ * _mftEntrySize);
  }
  else {
    if ((_mftIndex + 1) == (_clusterSize / _mftEntrySize))
      _currentRunIndex++;
    return _baseOffset + (_mftIndex++ * _mftEntrySize);
  }
}

void		Attribute::setDateToString(uint64_t value, struct tm **date, std::string *dateString, bool usecond)
{
  uint64_t	origValue;

  if (value > 0) {
    value -= NANOSECS_1601_TO_1970;
    origValue = value;
    value /= 10000000;
    *date = gmtime((time_t *)&(value));
    if (usecond) {
      std::ostringstream	nanoBuff;
      char			firstPart[100];

      strftime(firstPart, 100, "%a %b %d %Y %H:%M:%S.", *date);
      nanoBuff << firstPart << origValue - (((value * 10000000)));
      while (nanoBuff.str().size() < std::string("Day Mon DD YYYY HH:MM:SS.NNNNNNN").size()) {
	nanoBuff << '0';
      }
      *dateString = nanoBuff.str();
    }
    else {
      *dateString = std::string(asctime(*date));
      *dateString = dateString->substr(0, dateString->size() - 1);
    }
  }
  else {
    uint32_t zero = 0;
    *date = gmtime((time_t *)&zero);
    *dateString = std::string("Not set");
  }
}

void		Attribute::fixupOffsets(uint8_t fixupAmount)
{
  uint8_t	i = 0;

  if (_fixupIndexes == NULL) {
    _fixupIndexes = new uint64_t[fixupAmount];
    _fixupIndexesSize = fixupAmount;
  }
  if (fixupAmount > _fixupIndexesSize) {
    delete _fixupIndexes;
    _fixupIndexes = new uint64_t[fixupAmount];
    _fixupIndexesSize = fixupAmount;
  }

  while (i < _fixupIndexesSize) {
#if __WORDSIZE == 64
    _fixupIndexes[i++] = 0x0UL;
#else
    _fixupIndexes[i++] = 0x0ULL;
#endif
  }
}

void	Attribute::fixupOffset(uint8_t fixupIndex, uint64_t value)
{
  if (fixupIndex > _fixupIndexesSize) {
    throw(vfsError(std::string("Attribute::fixupOffset failed")));
  }
  _fixupIndexes[fixupIndex] = value;
#if __WORDSIZE == 64
  DEBUG(INFO, "fixup array %u set to 0x%lx\n", fixupIndex, value);
#else
  DEBUG(INFO, "fixup array %u set to 0x%llx\n", fixupIndex, value);
#endif
}

uint64_t	Attribute::getFixupOffset(uint8_t fixupIndex)
{
  return _fixupIndexes[fixupIndex];
}

std::string	Attribute::getName()
{
  return getName(_attributeHeader->attributeTypeIdentifier);
}

std::string	Attribute::getExtName()
{
  std::ostringstream	extName;
  uint8_t		i = 0;
  
  while (i < (_attributeHeader->nameLength * 2)) {
    extName << (char)*(_readBuffer + _bufferOffset + _attributeHeader->nameOffset + i);
    i += 2;
  }
  if (extName.str().size()) {
    return std::string(":") + extName.str();
  }
  return std::string("");
}

std::string		Attribute::getFullName()
{
  std::string		baseName = getName(_attributeHeader->attributeTypeIdentifier);
  std::ostringstream	extName;
  uint8_t		i = 0;

  DEBUG(INFO, "i is 0x%x nameLength is 0x%x bufferoffset 0x%x\n", i, _attributeHeader->nameLength, _bufferOffset + _attributeHeader->nameOffset);
  while (i < (_attributeHeader->nameLength * 2)) {
    DEBUG(INFO, "i is 0x%x nameLength is 0x%x bufferoffset 0x%x\n", i, _attributeHeader->nameLength, _bufferOffset + _attributeHeader->nameOffset);
    DEBUG(INFO, "Got %c\n", (char)*(_readBuffer + _bufferOffset + _attributeHeader->nameOffset + i));
    extName << (char)*(_readBuffer + _bufferOffset + _attributeHeader->nameOffset + i);
    i += 2;
  }
  if (extName.str().size()) {
    return baseName + std::string(":") + extName.str();
  }
  return baseName;    
}

std::string	Attribute::getName(uint32_t attributeType)
{
  if (attributeType == ATTRIBUTE_STANDARD_INFORMATION) {
    return std::string("$STANDARD_INFORMATION");
    ;
  }
  else if (attributeType == ATTRIBUTE_ATTRIBUTE_LIST) {
    return std::string("$ATTRIBUTE_LIST");
    ;
  }
  else if (attributeType == ATTRIBUTE_FILE_NAME) {
    return std::string("$FILE_NAME");
    ;
  }
  else if (attributeType == ATTRIBUTE_VOLUME_VERSION_OR_OBJECT_ID) {
    return std::string("$VOLUME_VERSION_OR_OBJECT_ID");
    ;
  }
  else if (attributeType == ATTRIBUTE_SECURITY_DESCRIPTOR) {
    return std::string("$SECURITY_DESCRIPTOR");
    ;
  }
  else if (attributeType == ATTRIBUTE_VOLUME_NAME) {
    return std::string("$VOLUME_NAME");
    ;
  }
  else if (attributeType == ATTRIBUTE_VOLUME_INFORMATION) {
    return std::string("$VOLUME_INFORMATION");
    ;
  }
  else if (attributeType == ATTRIBUTE_DATA) {
    return std::string("$DATA");
    ;
  }
  else if (attributeType == ATTRIBUTE_INDEX_ROOT) {
    return std::string("$INDEX_ROOT");
    ;
  }
  else if (attributeType == ATTRIBUTE_INDEX_ALLOCATION) {
    return std::string("$INDEX_ALLOCATION");
    ;
  }
  else if (attributeType == ATTRIBUTE_BITMAP) {
    return std::string("$BITMAP");
    ;
  }
  else if (attributeType == ATTRIBUTE_SYMBOLINC_LINK_OR_REPARSE_POINT) {
    return std::string("$SYMBOLINC_LINK_OR_REPARSE_POINT");
    ;
  }
  else if (attributeType == ATTRIBUTE_EA_INFORMATION) {
    return std::string("$EA_INFORMATION");
    ;
  }
  else if (attributeType == ATTRIBUTE_EA) {
    return std::string("$EA");\
    ;
  }
  else if (attributeType == ATTRIBUTE_LOGGED_UTILITY_STREAM) {
    return std::string("$LOGGED_UTILITY_STREAM");
    ;
  }
  return std::string("unknown");
}

/*


void				Attribute::_attributeSecurityDescriptor()
{
  AttributeSecurityDescriptor	*attribute = (AttributeSecurityDescriptor *)
    (_readBuffer + _bufferOffset +
     _attributeResidentDataHeader->contentOffset);

  ;
}

void			Attribute::_attributeVolumeName()
{
  AttributeVolumeName	*attribute = (AttributeVolumeName *)
    (_readBuffer + _bufferOffset +
     _attributeResidentDataHeader->contentOffset);

  ;
}

void				Attribute::_attributeVolumeInformation()
{
  AttributeVolumeInformation	*attribute = (AttributeVolumeInformation *)
    (_readBuffer + _bufferOffset +
     _attributeResidentDataHeader->contentOffset);

  ;
}

void			Attribute::_attributeBitmap()
{
  AttributeBitmap	*attribute = (AttributeBitmap *)
    (_readBuffer + _bufferOffset +
     _attributeResidentDataHeader->contentOffset);

  ;
}

void				Attribute::_attributeEAInformation()
{
  AttributeEAInformation	*attribute = (AttributeEAInformation *)
    (_readBuffer + _bufferOffset +
     _attributeResidentDataHeader->contentOffset);

  ;
}

void		Attribute::_attributeEA()
{
  AttributeEA	*attribute = (AttributeEA *)
    (_readBuffer + _bufferOffset +
     _attributeResidentDataHeader->contentOffset);

  ;
}

void				Attribute::_attributeLoggedUtilityStream()
{
  AttributeLoggedUtilityStream	*attribute = (AttributeLoggedUtilityStream *)
    (_readBuffer + _bufferOffset +
     _attributeResidentDataHeader->contentOffset);

  ;
}
*/
