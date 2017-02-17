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
#include "mftfile.hpp"

MftFile::MftFile(VFile *vfile, uint16_t mftEntrySize, uint16_t indexRecordSize,
		 uint16_t sectorSize, uint16_t clusterSize)
{
  _vfile = vfile;
  //  _offsetListSize = offsetListSize;
  _currentOffset = 0;
  //  _offsetList = new OffsetRun[_offsetListSize];
  _numberOfRecords = 0;

  _mftEntrySize = mftEntrySize;
  _indexRecordSize = indexRecordSize;
  _sectorSize = sectorSize;
  _clusterSize = clusterSize;

  _allocatedSize = 0;
}

MftFile::~MftFile()
{
  if (_data)
    delete _data;
  if (_bitmap)
    delete _bitmap;
}

uint16_t	MftFile::getOffsetListSize()
{
  return _data->getOffsetListSize();
}

uint32_t	MftFile::getNumberOfRecords()
{
  return _numberOfRecords;
}

MftEntry	*MftFile::get(uint64_t parentReference)
{
  uint32_t	fileReference;
  uint16_t	sequenceNumber;
  uint32_t	mftEntry;
  uint64_t	offset;
  MftEntry	*parent;

  fileReference = parentReference >> 32;
#if __WORDSIZE == 64
  DEBUG(INFO, "got reference: 0x%.16lx\n", parentReference);
  sequenceNumber = parentReference & 0xff000000UL;
  mftEntry = parentReference & 0xffffffUL;
  DEBUG(INFO, "searching for 0x%lx, got 0x%x\n", parentReference, mftEntry);
#else
  DEBUG(INFO, "got reference: 0x%.16llx\n", parentReference);
  sequenceNumber = parentReference & 0xff000000ULL;
  mftEntry = parentReference & 0xffffffULL;
  DEBUG(INFO, "searching for 0x%llx, got 0x%x\n", parentReference, mftEntry);
#endif
  if (mftEntry == MFTENTRY_ROOT)
    return NULL;
  DEBUG(INFO, "fileReference: 0x%x\n", fileReference);
  DEBUG(INFO, "sequenceNumber: 0x%x\n", sequenceNumber);
  DEBUG(INFO, "searching for mftEntry: 0x%x\n", mftEntry);

  if (!(offset = _data->offsetFromID(mftEntry)))
    return NULL;

#if __WORDSIZE == 64
  DEBUG(INFO, "parent is @ 0x%lx\n", offset);
#else
  DEBUG(INFO, "parent is @ 0x%llx\n", offset);
#endif

  parent = new MftEntry(_vfile); //XXX must find a real fix 
  parent->indexRecordSize(_indexRecordSize);
  parent->sectorSize(_sectorSize);
  parent->clusterSize(_clusterSize);
  parent->mftEntrySize(_mftEntrySize);
  DEBUG(INFO, "parent on da way\n");
  if (parent->decode(offset) == false) {
    delete parent;
    return NULL;
  }
  if (parent->getMftEntryBlock()->fixupArrayOffset > _mftEntrySize) {
    delete parent;
    return NULL;
  }
  DEBUG(INFO, "parent set !\n");
  return parent;
}

void					MftFile::dumpDiscoveredEntries()
{
  std::map<uint32_t, bool>::iterator	it;

  DEBUG(CRITICAL, "map size: %u items\n", (uint32_t)_discoveredEntries.size());
  it = _discoveredEntries.begin();
  while (it != _discoveredEntries.end()) {
    if (it->first && !(it->first % 20)) {
      DEBUG(CRITICAL, "\n");
    }
    else if (it->first && !(it->first % 10)) {
      DEBUG(CRITICAL, "  ");
    }
    else if (it->first && !(it->first % 5)) {
      DEBUG(CRITICAL, " ");
    }
    if (it->second) {
      DEBUG(CRITICAL, "X");
    }
    else {
      DEBUG(CRITICAL, ".");
    }
    it++;
  }
  DEBUG(CRITICAL, "\n");
}

uint32_t				MftFile::discoverPercent()
{
  return ((_discoveredEntries.size() * 100) / _numberOfRecords);
}

void		MftFile::entryDiscovered(uint32_t i)
{
  _discoveredEntries.insert(std::pair<uint32_t, bool>(i, true));
}

bool		MftFile::isEntryDiscovered(uint32_t i)
{
  return (_discoveredEntries.find(i) != _discoveredEntries.end());
}

void		MftFile::data(Attribute *dataAttribute)
{
  DEBUG(INFO, "setting data to mftmainfile\n");
  _data = new AttributeData(*dataAttribute);

  _data->mftEntrySize(_mftEntrySize);
  _data->indexRecordSize(_indexRecordSize);
  _data->sectorSize(_sectorSize);
  _data->clusterSize(_clusterSize);

  _data->setRunList();
  //  _numberOfRecords = _data->getRunAmount();
  _numberOfRecords = _data->getSize() / _mftEntrySize;

#if __WORDSIZE == 64
  DEBUG(CRITICAL, "number of mft records: %u datasize: %lu bytes mftentrysize %u\n", _numberOfRecords, _data->getSize(), _mftEntrySize);
#else
  DEBUG(CRITICAL, "number of mft records: %u datasize: %llu bytes mftentrysize %u\n", _numberOfRecords, _data->getSize(), _mftEntrySize);
#endif
}

void	MftFile::bitmap(Attribute *bitmapAttribute)
{
  _bitmap = new AttributeBitmap(*bitmapAttribute);

  _bitmap->setContent();
}

void	MftFile::standardInformation(Attribute *attribute)
{
  _standardInformation = new AttributeStandardInformation(*attribute);
  if (attribute->attributeHeader()->nonResidentFlag)
    _standardInformation->setRunList();
}

void	MftFile::fileName(Attribute *attribute)
{
  _fileName = new AttributeFileName(*attribute);
  if (attribute->attributeHeader()->nonResidentFlag)
    _fileName->setRunList();
}

void	MftFile::securityDescriptor(Attribute *attribute)
{
  _securityDescriptor = new AttributeSecurityDescriptor(*attribute);
    if (attribute->attributeHeader()->nonResidentFlag) {
    _securityDescriptor->setRunList();
  }
}

void	MftFile::indexRoot(Attribute *attribute)
{
  _indexRoot = new AttributeIndexRoot(*attribute);
}

void	MftFile::indexAllocation(Attribute *attribute)
{
  _indexAllocation = new AttributeIndexAllocation(*attribute);

  _indexAllocation->mftEntrySize(_mftEntrySize);
  _indexAllocation->indexRecordSize(_indexRecordSize);
  _indexAllocation->sectorSize(_sectorSize);
  _indexAllocation->clusterSize(_clusterSize);

  DEBUG(INFO, "sizes: 0x%x 0x%x 0x%x 0x%x\n", _indexAllocation->mftEntrySize(), _indexAllocation->indexRecordSize(), _indexAllocation->sectorSize(), _indexAllocation->clusterSize());

  if (attribute->attributeHeader()->nonResidentFlag)
    _indexAllocation->setRunList();
}
