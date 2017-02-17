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

#include "indexroot.hpp"

AttributeIndexRoot::AttributeIndexRoot(Attribute &parent)
{
  _attributeHeader = new AttributeHeader(*(parent.attributeHeader()));
  _attributeResidentDataHeader = new AttributeResidentDataHeader(*(parent.residentDataHeader()));

  _readBuffer = parent.readBuffer();
  _attributeOffset = parent.attributeOffset();
  _bufferOffset = parent.bufferOffset();
  _offsetInRun = 0;
  _offsetRunIndex = 0;

  _data = new AttributeIndexRoot_t(*(AttributeIndexRoot_t *)(_readBuffer + _bufferOffset +
							     _attributeResidentDataHeader->contentOffset));
  _nodeHeader = new NodeHeader(*(NodeHeader *)(_readBuffer + _bufferOffset +
					       _attributeResidentDataHeader->contentOffset +
					       ATTRIBUTE_INDEXROOT_SIZE));

  _currentRelativeOffset = _nodeHeader->relOffsetStart;
  _baseReadingOffset = _bufferOffset + ATTRIBUTE_INDEXROOT_SIZE +
    _attributeResidentDataHeader->contentOffset;
  _nextVCN = 0;
  _baseOffset = parent.baseOffset();
  _lastEntryFound = false;
  _attributeRealOffset = parent.attributeRealOffset();

  _entriesAmount = _saveEntries();

  DEBUG(INFO, "found %u entries\n", _entriesAmount);

  //  content();
}

AttributeIndexRoot::~AttributeIndexRoot()
{
  ;
}

uint32_t	AttributeIndexRoot::_saveEntries()
{
  uint32_t	entriesCount = 0;
  uint32_t	currentOffset = _nodeHeader->relOffsetStart;
  uint32_t	baseOffset = _bufferOffset + ATTRIBUTE_INDEXROOT_SIZE +
    _attributeResidentDataHeader->contentOffset;
  IndexEntry	*indexEntry;
  
  while (currentOffset < _nodeHeader->relOffsetEndAlloc) {
    indexEntry = (IndexEntry *)(_readBuffer + currentOffset + baseOffset);
    DEBUG(INFO, "indexEntryContentLength %u\n", indexEntry->contentLength);
    if (indexEntry->contentLength) {
      entriesCount++;
    }
    currentOffset += indexEntry->entryLength;
  }
  
  if (!entriesCount) {
    _indexEntries = NULL;
    _currentIndexEntry = 0;
    return 0;
  }
  _indexEntries = new IndexEntry *[entriesCount];
  _entriesContent = new uint8_t *[entriesCount];

  entriesCount = 0;
  currentOffset = _nodeHeader->relOffsetStart;
  while (currentOffset < _nodeHeader->relOffsetEndAlloc) {
    uint16_t	i = 0;

    indexEntry = (IndexEntry *)(_readBuffer + currentOffset + baseOffset);
    if (indexEntry->contentLength) {
      _indexEntries[entriesCount] = new IndexEntry(*indexEntry);
      _entriesContent[entriesCount] = new uint8_t[indexEntry->contentLength];
      while (i < indexEntry->contentLength) {
	_entriesContent[entriesCount] = (_readBuffer + currentOffset +
					 baseOffset +
					 INDEX_ENTRY_SIZE + i);
	i++;
      }
      entriesCount++;
    }
    currentOffset += indexEntry->entryLength;
  }
  _currentIndexEntry = 0;
  return entriesCount;
}

bool			AttributeIndexRoot::hasNext()
{
  DirectoryIndexEntry	*indexEntry;

  if (_currentIndexEntry >= _entriesAmount || !_entriesAmount) {
    _currentMftEntry = 0;
    return false;
  }

#if __WORDSIZE == 64
  DEBUG(INFO, "base offset ? 0x%lx\n", _baseOffset);
#else
  DEBUG(INFO, "base offset ? 0x%llx\n", _baseOffset);
#endif

  indexEntry = (DirectoryIndexEntry *)_indexEntries[_currentIndexEntry];
  if (!indexEntry->fileNameMFTFileReference) {
    _currentMftEntry = 0;
    return false;
  }

  _currentRelativeOffset += indexEntry->entryLength;
#if __WORDSIZE == 64
  DEBUG(INFO, "indexEntry: fileRef: 0x%lx\n\tentryLength: 0x%x\n\tfileNameLength: 0x%x\n", indexEntry->fileNameMFTFileReference, indexEntry->entryLength, indexEntry->fileNameLength);
  _currentMftEntry = indexEntry->fileNameMFTFileReference & 0xffffffUL;
#else
  DEBUG(INFO, "indexEntry: fileRef: 0x%llx\n\tentryLength: 0x%x\n\tfileNameLength: 0x%x\n", indexEntry->fileNameMFTFileReference, indexEntry->entryLength, indexEntry->fileNameLength);
  _currentMftEntry = indexEntry->fileNameMFTFileReference & 0xffffffULL;
#endif
  DEBUG(INFO, "_currentMftEntry is now %u\n", _currentMftEntry);
  _currentLength = _indexEntries[_currentIndexEntry]->entryLength;
  _currentIndexEntry++;
  return true;
}

uint32_t	AttributeIndexRoot::nextMftEntry()
{
  DEBUG(INFO, "_currentMftEntry return %u\n", _currentMftEntry);
  return _currentMftEntry;
}

void	AttributeIndexRoot::content()
{

  printf("\tType of attribute in index 0x%x: %s\n", _data->attributeInIndexType, getName(_data->attributeInIndexType).c_str());
  printf("\tCollation sorting rule 0x%x\n", _data->collationSortingRule);
  printf("\tSize of each index record in bytes 0x%x\n", _data->indexRecordSizeBytes);

  printf("\tSize of each index record in clusters 0x%x\n", _data->indexRecordSizeClusters);
  printf("\tUnused 0x%.2x%.2x%.2x\n", _data->unused[0], _data->unused[1], _data->unused[2]);


  printf("\trelOffsetStart 0x%x\n", _nodeHeader->relOffsetStart);
  printf("\trelOffsetEndUsed 0x%x\n", _nodeHeader->relOffsetEndUsed);
  printf("\trelOffsetEndAlloc 0x%x\n", _nodeHeader->relOffsetEndAlloc);
  if (_nodeHeader->flags == ENTRY_CHILD_NODE_EXIST) {
    printf("\tflags 0x%x: child node exist\n", _nodeHeader->flags);
  }

  if (_data->attributeInIndexType == ATTRIBUTE_FILE_NAME) {
    uint32_t	currentOffset = _nodeHeader->relOffsetStart;
    uint32_t	baseOffset = _bufferOffset + ATTRIBUTE_INDEXROOT_SIZE +
      _attributeResidentDataHeader->contentOffset;
    IndexEntry	*indexEntry;

    while (currentOffset < _nodeHeader->relOffsetEndAlloc) {
      indexEntry = (IndexEntry *)(_readBuffer + currentOffset + baseOffset);

      printf("\tEntry at index 0x%x:\n", currentOffset);
      printf("\t\tentryLength: 0x%x\n", indexEntry->entryLength);
      printf("\t\tcontentLength: 0x%x\n", indexEntry->contentLength);
      if (indexEntry->flags & ENTRY_CHILD_NODE_EXIST)
	printf("\t\tHas child\n");
      if (indexEntry->flags & ENTRY_LAST_ONE)
	printf("\t\tIs the last entry\n");
      currentOffset += indexEntry->entryLength;
      
    }
  }
  printf("\n");
}

uint32_t	AttributeIndexRoot::indexRecordSizeBytes()
{
  return _data->indexRecordSizeBytes;
}

uint32_t	AttributeIndexRoot::currentEntryLength()
{
  if (_currentIndexEntry > _entriesAmount || !_entriesAmount) {
    return 0;
  }
  return _currentLength;
}

bool	AttributeIndexRoot::canGetNext()
{
  return (_currentIndexEntry >= _entriesAmount || !_entriesAmount);
}
