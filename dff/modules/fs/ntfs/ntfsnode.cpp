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

#include "ntfsnode.hpp"

#include <sstream>

NtfsNode::NtfsNode(std::string Name, uint64_t size, Node *parent,
		   Ntfs *fsobj, bool isFile, AttributeFileName *metaFileName,
		   AttributeStandardInformation *metaStandardInformation,
		   MftEntry *mft):
  Node(Name, size, parent, fsobj)
{
  _metaFileName = metaFileName;
  if (metaStandardInformation) {
    _SI = new AttributeStandardInformation(*metaStandardInformation);
  }
  else {
    _SI = NULL;
  }
  _isFile = isFile;
  if (isFile) {
    this->setFile();
    setSize(size);
  }
  else {
    this->setDir();
  }
  _mftEntry = 0;
  _physOffset = 0;
  _mft = mft;
  _data = NULL;
  setSize(size);
  _bootBlock = NULL;
}

NtfsNode::NtfsNode(std::string Name, uint64_t size, Node *parent,
		   Ntfs *fsobj, bool isFile, AttributeFileName *metaFileName,
		   AttributeStandardInformation *metaStandardInformation,
		   MftEntry *mft, uint32_t mftEntry, uint64_t offset):
  Node(Name, size, parent, fsobj)
{
  _metaFileName = metaFileName;
  if (metaStandardInformation) {
    _SI = new AttributeStandardInformation(*metaStandardInformation);
  }
  else {
    _SI = NULL;
  }
  _isFile = isFile;
#if __WORDSIZE == 64
  DEBUG(INFO, "%s %lu\n", Name.c_str(), size);
#else
  DEBUG(INFO, "%s %llu\n", Name.c_str(), size);
#endif
  if (isFile) {
    this->setFile();
    setSize(size);
  }
  else
    this->setDir();
  _mftEntry = mftEntry;
  _physOffset = offset;
  _mft = mft;
  _data = NULL;
  _bootBlock = NULL;
}

NtfsNode::NtfsNode(std::string Name, uint64_t size, Node *parent,
		   Ntfs *fsobj, BootBlock *bootBlock):
  Node(Name, size, parent, fsobj)
{
  _isFile = false;
  _metaFileName = NULL;
  _SI = NULL;
  _mft = NULL;
  _mftEntry = 0;
  _physOffset = 0;
  _data = NULL;
  this->setDir();
  setSize(0);
  _bootBlock = bootBlock;
}


NtfsNode::~NtfsNode()
{
  ;
}

std::map<std::string, Variant_p >	NtfsNode::_headerToAttribute(Attribute *attr)
{
  std::map<std::string, Variant_p >	headerMap;
  std::map<std::string, Variant_p >	flagsMap;
  std::ostringstream				stringBuff;
  
  headerMap["Length"] = Variant_p(new Variant(attr->attributeHeader()->attributeLength));
  headerMap["Is non-resident"] = Variant_p(new Variant(attr->attributeHeader()->nonResidentFlag));
  headerMap["Name length"] = Variant_p(new Variant(attr->attributeHeader()->nameLength));
  headerMap["Attribute number"] = Variant_p(new Variant(attr->attributeHeader()->attributeIdentifier));
  
  flagsMap["Value"] = Variant_p(new Variant(attr->attributeHeader()->flags));
  flagsMap["Compressed"] = Variant_p(new Variant((attr->attributeHeader()->flags & ATTRIBUTE_FLAG_COMPRESSED) > 0));
  flagsMap["Encrypted"] = Variant_p(new Variant((attr->attributeHeader()->flags & ATTRIBUTE_FLAG_ENCRYPTED) > 0));
  flagsMap["Sparse"] = Variant_p(new Variant((attr->attributeHeader()->flags & ATTRIBUTE_FLAG_SPARSE) > 0));
  flagsMap["Unknown flag present"] = Variant_p(new Variant((attr->attributeHeader()->flags && !(attr->attributeHeader()->flags & ATTRIBUTE_FLAG_COMPRESSED) && !(attr->attributeHeader()->flags & ATTRIBUTE_FLAG_ENCRYPTED) && !(attr->attributeHeader()->flags & ATTRIBUTE_FLAG_SPARSE))));

  headerMap["Flags"] = Variant_p(new Variant(flagsMap));
  
  if (attr->attributeHeader()->nonResidentFlag) 
    {
      headerMap["Starting VCN"] = Variant_p(new Variant(attr->nonResidentDataHeader()->startingVCN));
      headerMap["Ending VCN"] = Variant_p(new Variant(attr->nonResidentDataHeader()->endingVCN));
      headerMap["Run-list offset"] = Variant_p(new Variant(attr->nonResidentDataHeader()->runListOffset));
      headerMap["Compression unit size"] = Variant_p(new Variant(attr->nonResidentDataHeader()->compressionUnitSize));
      headerMap["Content allocated size"] = Variant_p(new Variant(attr->nonResidentDataHeader()->attributeContentAllocatedSize));
      headerMap["Content actual size"] = Variant_p(new Variant(attr->nonResidentDataHeader()->attributeContentActualSize));
      headerMap["Content initialized size"] = Variant_p(new Variant(attr->nonResidentDataHeader()->attributeContentInitializedSize));
    }
  else 
    {
      headerMap["Content size"] = Variant_p(new Variant(attr->residentDataHeader()->contentSize));
      headerMap["Content offset"] = Variant_p(new Variant(attr->residentDataHeader()->contentOffset));
    }
  return headerMap;
}


Attributes				NtfsNode::_attributes()
{
  Attributes	attr;

  DEBUG(INFO, "in extended attributes\n");

  dff::ScopedMutex	locker(dynamic_cast< Ntfs* >(this->fsobj())->_mutex);
  if (this->_bootBlock) {
    uint16_t	clusterSize = this->_bootBlock->bytePerSector * this->_bootBlock->sectorPerCluster;
    // We are in a root NTFS node, populates it with NTFS parameters
    attr["Byte per sector"] = Variant_p(new Variant(this->_bootBlock->bytePerSector));
    attr["Sector per cluster"] = Variant_p(new Variant(this->_bootBlock->sectorPerCluster));
    attr["Cluster byte size"] = Variant_p(new Variant(clusterSize));
    attr["Number of sector"] = Variant_p(new Variant(this->_bootBlock->numberOfSector));
    attr["Number of byte"] = Variant_p(new Variant(this->_bootBlock->numberOfSector * clusterSize));
    attr["MFT start cluster"] = Variant_p(new Variant(this->_bootBlock->startMft));
    attr["MFT start address"] = Variant_p(new Variant(this->_bootBlock->startMft * clusterSize));
    attr["MFTMirr start cluster"] = Variant_p(new Variant(this->_bootBlock->startMftMirr));
    attr["MFTMirr start address"] = Variant_p(new Variant(this->_bootBlock->startMftMirr * clusterSize));
    attr["MFT record cluster size"] = Variant_p(new Variant(this->_bootBlock->clusterMftRecord));
    attr["MFT record byte size"] = Variant_p(new Variant(this->_bootBlock->clusterMftRecord * clusterSize));
    attr["Index record cluster size"] = Variant_p(new Variant(this->_bootBlock->clusterIndexRecord));
    attr["Index record byte size"] = Variant_p(new Variant(this->_bootBlock->clusterIndexRecord * clusterSize));
    attr["Volume serial number"] = Variant_p(new Variant(this->_bootBlock->volumeSerialNumber));
  }

  if (!(this->_SI)) {
    return attr;
  }

  attr["MFT entry number"] = Variant_p(new Variant(this->_mftEntry));
  attr["MFT physical offset"] = Variant_p(new Variant(this->_physOffset));
  attr["MFT cluster number"] = Variant_p(new Variant(this->_physOffset / this->_SI->clusterSize()));

  Attribute	*attribute;

  attr["altered"] = Variant_p(new Variant(new vtime(this->_SI->data()->fileAlteredTime, TIME_MS_64)));
  attr["accessed"] = Variant_p(new Variant(new vtime(this->_SI->data()->fileAccessedTime, TIME_MS_64)));
  attr["creation"] = Variant_p(new Variant(new vtime(this->_SI->data()->creationTime, TIME_MS_64)));

  if (!(this->_mft->decode(this->_physOffset))) {
    return attr;
  }

  while ((attribute = (this->_mft->getNextAttribute()))) {
    std::map<std::string, Variant_p >	attributeMap;
    std::string				attributeFullName;
    std::map<std::string, Variant_p >	attributeHeaderMap;
    
    attribute->readHeader();
    attributeFullName = attribute->getFullName();
    attributeHeaderMap = this->_headerToAttribute(attribute);

    if (attribute->getType() == ATTRIBUTE_STANDARD_INFORMATION) {
      this->_standardInformation(&attributeMap, new AttributeStandardInformation(*attribute));
    }
    else if (attribute->getType() == ATTRIBUTE_FILE_NAME) {
      this->_fileName(&attributeMap, new AttributeFileName(*attribute));
    }
    else if (attribute->getType() == ATTRIBUTE_DATA) {
      // Creates a 'Runs list' vmap made of every data chunk addresses.
      // FIXME does it impact performances ? Toggle it with a module argument.
      this->_dataAttribute(&attributeMap, new AttributeData(*attribute));
    }
    DEBUG(INFO, "got name: %s\n", attributeFullName.c_str());
    attributeMap.insert(std::pair<std::string, Variant_p >("Header", Variant_p(new Variant(attributeHeaderMap))));
    attributeMap.insert(std::pair<std::string, Variant_p >("Offset", Variant_p(new Variant(attribute->attributeOffset()))));
    attr[attributeFullName] = Variant_p(new Variant(attributeMap));    
  }
  delete attribute;
  return attr;
}

void	NtfsNode::_standardInformation(std::map<std::string, Variant_p > *vmap, AttributeStandardInformation *nAttr)
{
  std::map<std::string, Variant_p >	flagsMap;

  flagsMap["Value"] = Variant_p(new Variant(nAttr->data()->flags));
  flagsMap["Read only"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_READ_ONLY) > 0));
  flagsMap["Hidden"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_HIDDEN) > 0));
  flagsMap["System"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SYSTEM) > 0));
  flagsMap["Archive"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_ARCHIVE) > 0));
  flagsMap["Device"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_DEVICE) > 0));
  flagsMap["#Normal"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SHARPNORMAL) > 0));
  flagsMap["Temporary"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_TEMPORARY) > 0));
  flagsMap["Sparse"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SPARSE_FILE) > 0));
  flagsMap["Reparse point"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_REPARSE_POINT) > 0));
  flagsMap["Compressed"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_COMPRESSED) > 0));
  flagsMap["Offline"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_OFFLINE) > 0));
  flagsMap["Content is not being indexed for faster searches"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_CONTENT_NOT_INDEXED) > 0));
  flagsMap["Encrypted"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_ENCRYPTED) > 0));
  flagsMap["Directory"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_DIRECTORY) > 0));
  flagsMap["Index view"] = Variant_p(new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_INDEX_VIEW) > 0));
  flagsMap["Unknown flag present"] = Variant_p(new Variant((nAttr->data()->flags && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_READ_ONLY) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_HIDDEN) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SYSTEM) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_ARCHIVE) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_DEVICE) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SHARPNORMAL) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_TEMPORARY) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SPARSE_FILE) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_REPARSE_POINT) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_COMPRESSED) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_OFFLINE) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_CONTENT_NOT_INDEXED) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_ENCRYPTED) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_DIRECTORY) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_INDEX_VIEW))));

  (*vmap)["Creation time"] = Variant_p(new Variant(new vtime(nAttr->data()->creationTime, TIME_MS_64)));
  (*vmap)["File altered time"] = Variant_p(new Variant(new vtime(nAttr->data()->fileAlteredTime, TIME_MS_64)));
  (*vmap)["MFT altered time"] = Variant_p(new Variant(new vtime(nAttr->data()->mftAlteredTime, TIME_MS_64)));
  (*vmap)["File accessed time"] = Variant_p(new Variant(new vtime(nAttr->data()->fileAccessedTime, TIME_MS_64)));

  (*vmap)["Flags"] = Variant_p(new Variant(flagsMap));
  (*vmap)["Max number of versions"] = Variant_p(new Variant(nAttr->data()->maxNumberOfVersions));
  (*vmap)["Version number"] = Variant_p(new Variant(nAttr->data()->versionNumber));
  (*vmap)["Class ID"] = Variant_p(new Variant(nAttr->data()->classID));
  (*vmap)["Owner ID"] = Variant_p(new Variant(nAttr->data()->ownerID));
  (*vmap)["Security ID"] = Variant_p(new Variant(nAttr->data()->securityID));
  (*vmap)["Quota charged"] = Variant_p(new Variant(nAttr->data()->quotaCharged));
  (*vmap)["Update sequence number"] = Variant_p(new Variant(nAttr->data()->updateSequenceNumber));
  delete nAttr;
}

void	NtfsNode::_fileName(std::map<std::string, Variant_p > *vmap, AttributeFileName *nAttr)
{
  (*vmap)["Creation time"] = Variant_p(new Variant(new vtime(nAttr->data()->fileCreationTime, TIME_MS_64)));
  (*vmap)["File altered time"] = Variant_p(new Variant(new vtime(nAttr->data()->fileModificationTime, TIME_MS_64)));
  (*vmap)["MFT altered time"] = Variant_p(new Variant(new vtime(nAttr->data()->mftModificationTime, TIME_MS_64)));
  (*vmap)["File accessed time"] = Variant_p(new Variant(new vtime(nAttr->data()->fileAccessTime, TIME_MS_64)));
  
  delete nAttr;
}

void					NtfsNode::_dataAttribute(std::map<std::string, Variant_p > *vmap, AttributeData *data)
{
  std::map<std::string, Variant_p >	runMap;
  OffsetRun				*run;

  if (!data->attributeHeader()->nonResidentFlag || !data->getOffsetListSize())
    return;

  run = data->getOffsetRun(0);
  runMap["length"] = Variant_p(new Variant(run->runLength));
  runMap["cluster"] = Variant_p(new Variant(run->runOffset));
  (*vmap)["First chunk"] = Variant_p(new Variant(runMap));
  (*vmap)["Number of chunk"] = Variant_p(new Variant(data->getOffsetListSize()));

  delete data;
}

void	NtfsNode::fileMapping(FileMapping *fm)
{
  if (_isFile && size()) {
    if (_data->attributeHeader()->nonResidentFlag) {
      DEBUG(CRITICAL, "NtfsNode::fileMapping nonResident\n");
      _offsetFromRunList(fm);
    }
    else {
      DEBUG(CRITICAL, "NtfsNode::fileMapping resident\n");
      _offsetResident(fm);
    }
  }
}

/**
 * Set data chunks for data inside of MFT attribute
 *  Fixups values are present in the last two bytes of sector
 *
 *  TODO if mftEntrySize > sectorSize * 2 ; we need to loop to replace fixup
 */
void	NtfsNode::_offsetResident(FileMapping *fm)
{
  uint16_t	dataStart = _data->residentDataHeader()->contentOffset +
    _data->getAttributeOffset();
  uint16_t	firstChunkSize = _data->getSectorSize() - SIZE_2BYTES -
    dataStart;
  uint16_t	remainSize = size() - firstChunkSize - SIZE_2BYTES;

  DEBUG(CRITICAL, "\tdataStart: 0x%x\n", dataStart);
  DEBUG(CRITICAL, "\tsectorSize - 2: 0x%x\n", _data->getSectorSize() - 2);
#if __WORDSIZE == 64
  DEBUG(CRITICAL, "\tfirst fixup: 0x%lx\n", _physOffset + _data->getFixupOffset(0));
#else
  DEBUG(CRITICAL, "\tfirst fixup: 0x%llx\n", _physOffset + _data->getFixupOffset(0));
#endif

  fm->push(0, firstChunkSize, _node, _data->getOffset());
  fm->push(firstChunkSize, SIZE_2BYTES, _node, _physOffset + _data->getFixupOffset(0));
  fm->push(firstChunkSize + SIZE_2BYTES, remainSize, _node, SIZE_2BYTES +
	   firstChunkSize + _data->getOffset());

}

/**
 * Set data chunks for data outside of MFT attribute, offsets are in a runlist
 */
void		NtfsNode::_offsetFromRunList(FileMapping *fm)
{
  uint16_t	currentRunIndex = 0;
  uint64_t	currentOffset = 0;
  uint64_t	registeredClusters = 0;
  uint64_t	newSize;
  AttributeData	currentData = *(_data);
  uint16_t	offsetListSize = currentData.getOffsetListSize();

  OffsetRun	*run;

  DEBUG(CRITICAL, "Offset list size: %u\n", offsetListSize);
  while ((currentRunIndex < offsetListSize)) {
    run = currentData.getOffsetRun(currentRunIndex);

    newSize = (run->runLength - registeredClusters) * currentData.clusterSize();

    if (run->runOffset) {						//1.1 + 2.1 + 3.1
      if (currentOffset + newSize > currentData.getSize()) {		//1.1
	if ((currentOffset + newSize) > currentData.getInitSize() && currentData.getSize() > currentData.getInitSize()) {
	  // > initSize, need to create shadow node
	  fm->push(currentOffset, currentData.getInitSize() - currentOffset,
		   _node, run->runOffset * currentData.clusterSize());
	  fm->push(currentOffset + (currentData.getInitSize() - currentOffset),
		   newSize - (currentData.getInitSize() - currentOffset), NULL, 0);
#if __WORDSIZE == 64
	  DEBUG(CRITICAL, "FM0.1 for offset 0x%lx push size 0x%lx at origin offset 0x%lx\n", currentOffset, currentData.getInitSize() - currentOffset, run->runOffset * currentData.clusterSize());
	  DEBUG(CRITICAL, "FM0.1 for offset 0x%lx push size 0x%lx as shadow (empty content)\n", currentOffset + (currentData.getInitSize() - currentOffset), newSize - (currentData.getInitSize() - currentOffset));
#else
	  DEBUG(CRITICAL, "FM0.1 for offset 0x%llx push size 0x%llx at origin offset 0x%llx\n", currentOffset, currentData.getInitSize() - currentOffset, run->runOffset * currentData.clusterSize());
	  DEBUG(CRITICAL, "FM0.1 for offset 0x%llx push size 0x%llx as shadow (empty content)\n", currentOffset + (currentData.getInitSize() - currentOffset), newSize - (currentData.getInitSize() - currentOffset));
#endif
	}
	else {
	  fm->push(currentOffset, newSize - (currentOffset + newSize - currentData.getSize()),
		   _node, run->runOffset * currentData.clusterSize());
#if __WORDSIZE == 64
	  DEBUG(CRITICAL, "FM1.1 for offset 0x%lx push size 0x%lx at origin offset 0x%lx\n", currentOffset, newSize - (currentOffset + newSize - currentData.getSize()), run->runOffset * currentData.clusterSize());
#else
	  DEBUG(CRITICAL, "FM1.1 for offset 0x%llx push size 0x%llx at origin offset 0x%llx\n", currentOffset, newSize - (currentOffset + newSize - currentData.getSize()), run->runOffset * currentData.clusterSize());
#endif
	}
      }
      else {								//2.1 + 3.1
	if ((currentOffset + newSize) > currentData.getInitSize()) {	//2.1
	  // > initSize, need to create shadow node
	  fm->push(currentOffset, currentData.getInitSize() - currentOffset,
		   _node, run->runOffset * currentData.clusterSize());
#if __WORDSIZE == 64
	  DEBUG(CRITICAL, "FM2.1 for offset 0x%lx push size 0x%lx at origin offset 0x%lx\n", currentOffset, currentData.getInitSize() - currentOffset, run->runOffset * currentData.clusterSize());
#else
	  DEBUG(CRITICAL, "FM2.1 for offset 0x%llx push size 0x%llx at origin offset 0x%llx\n", currentOffset, currentData.getInitSize() - currentOffset, run->runOffset * currentData.clusterSize());
#endif
	  fm->push(currentOffset + (currentData.getInitSize() - currentOffset),
		   newSize - (currentData.getInitSize() - currentOffset), NULL, 0);
#if __WORDSIZE == 64
	  DEBUG(CRITICAL, "FM2.1 for offset 0x%lx push size 0x%lx as shadow (empty content)\n", currentOffset + (currentData.getInitSize() - currentOffset), newSize - (currentData.getInitSize() - currentOffset));
#else
	  DEBUG(CRITICAL, "FM2.1 for offset 0x%llx push size 0x%llx as shadow (empty content)\n", currentOffset + (currentData.getInitSize() - currentOffset), newSize - (currentData.getInitSize() - currentOffset));
#endif
	}
	else {								//3.1
	  fm->push(currentOffset, newSize, _node, run->runOffset * currentData.clusterSize());
#if __WORDSIZE == 64
	  DEBUG(CRITICAL, "FM3.1 for offset 0x%lx push size 0x%lx at origin offset 0x%lx\n", currentOffset, newSize, run->runOffset * currentData.clusterSize());
#else
	  DEBUG(CRITICAL, "FM3.1 for offset 0x%llx push size 0x%llx at origin offset 0x%llx\n", currentOffset, newSize, run->runOffset * currentData.clusterSize());
#endif
	}
      }
    }
    else { // shadow							//4.1
      fm->push(currentOffset, newSize, NULL, 0);
#if __WORDSIZE == 64
      DEBUG(CRITICAL, "FM4.1 for offset 0x%lx push size 0x%lx as shadow (empty content)\n", currentOffset, newSize);
#else
      DEBUG(CRITICAL, "FM4.1 for offset 0x%llx push size 0x%llx as shadow (empty content)\n", currentOffset, newSize);
#endif
    }

    currentOffset += (run->runLength - registeredClusters) * currentData.clusterSize();
    registeredClusters = run->runLength;

    currentRunIndex++;
    if (currentRunIndex >= offsetListSize && _dataOffsets.size() > 1) {
      // There are several $DATA attributes, we have to fetch the next one.
      // We also have to take care of $DATA attribute's name because of ADS
      // feature, we should rely of next valid VCN.
#if __WORDSIZE == 64
      DEBUG(CRITICAL, "starting VCN 0x%lx ending VCN 0x%lx\n", currentData.nonResidentDataHeader()->startingVCN, currentData.nonResidentDataHeader()->endingVCN);
#else
      DEBUG(CRITICAL, "starting VCN 0x%llx ending VCN 0x%llx\n", currentData.nonResidentDataHeader()->startingVCN, currentData.nonResidentDataHeader()->endingVCN);
#endif
      _setNextAttrData(fm, currentOffset);
    }
  }
  DEBUG(CRITICAL, "\n");
}

void					NtfsNode::_setNextAttrData(FileMapping *fm, uint64_t totalOffset) {
  std::list<uint64_t>::const_iterator	iter(_dataOffsets.begin());
  std::list<uint64_t>::const_iterator	listend(_dataOffsets.end());
  MftEntry				*externalData;
  VFile					*vfile;
  Attribute				*attribute;
  AttributeData				*data;
  uint64_t				totalSize = _data->getSize();
  uint64_t				initSize = _data->getInitSize();

  if (!_SI || _dataOffsets.size() <= 1) {
    DEBUG(CRITICAL, "No $STANDARD_INFORMATION attribute, returns\n");
    return ;
  }
  // TODO _dataOffsets list should be ordered by VCN, but it seams to be done
  // in $ATTRIBUTE_LIST.

  // Init mft decoder
  vfile = _node->open();
  externalData = new MftEntry(vfile);
  // Init sizes from previously registered attribute _data
  externalData->clusterSize(_data->clusterSize());
  externalData->indexRecordSize(_data->indexRecordSize());
  externalData->sectorSize(_data->sectorSize());
  externalData->mftEntrySize(_data->mftEntrySize());

  // First $DATA attribute is _data, has already been mapped above,
  // so increment iter.
  ++iter;
  while (iter != listend) {
    if (externalData->decode(*iter)) {
      while ((attribute = externalData->getNextAttribute())) {
	attribute->readHeader();
	if (attribute->getType() == ATTRIBUTE_DATA) {
	  data = new AttributeData(*attribute);
#if __WORDSIZE == 64
	  DEBUG(CRITICAL, "data @ 0x%lx starting VCN 0x%lx ending VCN 0x%lx\n", *iter, data->nonResidentDataHeader()->startingVCN, data->nonResidentDataHeader()->endingVCN);
#else
	  DEBUG(CRITICAL, "data @ 0x%llx starting VCN 0x%llx ending VCN 0x%llx\n", *iter, data->nonResidentDataHeader()->startingVCN, data->nonResidentDataHeader()->endingVCN);
#endif
	  // TODO Same code as in _offsetFromRunList( merge in one func ?
	  uint16_t	currentRunIndex = 0;
	  uint64_t	currentOffset = 0;
	  uint64_t	newSize;
	  uint16_t	offsetListSize = data->getOffsetListSize();
	  uint64_t	registeredClusters = 0;

	  OffsetRun	*run;

	  DEBUG(CRITICAL, "Offset list size: %u\n", offsetListSize);
	  while ((currentRunIndex < offsetListSize)) {
	    run = data->getOffsetRun(currentRunIndex);
	    
	    newSize = (run->runLength - registeredClusters) * data->clusterSize();
	    if (run->runOffset) {
	      if (currentOffset + newSize > totalSize) {
		// XXX if > initSize, need to create shadow node
		fm->push(totalOffset, newSize - (currentOffset + newSize - totalSize),
			 _node, run->runOffset * data->clusterSize());
#if __WORDSIZE == 64
		DEBUG(CRITICAL, "FM1.2 for offset 0x%lx push size 0x%lx at origin offset 0x%lx\n", totalOffset, newSize - (currentOffset + newSize - totalSize), run->runOffset * data->clusterSize());
#else
		DEBUG(CRITICAL, "FM1.2 for offset 0x%llx push size 0x%llx at origin offset 0x%llx, runLength 0x%x clustSize 0x%x\n", totalOffset, newSize - (currentOffset + newSize - totalSize), run->runOffset * data->clusterSize(), run->runLength, data->clusterSize());
#endif
	      }
	      else {
		if ((currentOffset + newSize) > initSize) {
		  // > initSize, need to create shadow node
		  fm->push(totalOffset, initSize - currentOffset,
			   _node, run->runOffset * data->clusterSize());
#if __WORDSIZE == 64
		  DEBUG(CRITICAL, "FM2.2 for offset 0x%lx push size 0x%lx at origin offset 0x%lx\n", totalOffset, initSize - currentOffset, run->runOffset * data->clusterSize());
#else
		  DEBUG(CRITICAL, "FM2.2 for offset 0x%llx push size 0x%llx at origin offset 0x%llx\n", totalOffset, initSize - currentOffset, run->runOffset * data->clusterSize());
#endif
		  fm->push(totalOffset + (initSize - currentOffset),
			   newSize - (initSize - currentOffset), NULL, 0);
#if __WORDSIZE == 64
		  DEBUG(CRITICAL, "FM2.2 for offset 0x%lx push size 0x%lx as shadow (empty content)\n", totalOffset + (initSize - currentOffset), newSize - (initSize - currentOffset));
#else
		  DEBUG(CRITICAL, "FM2.2 for offset 0x%llx push size 0x%llx as shadow (empty content)\n", totalOffset + (initSize - currentOffset), newSize - (initSize - currentOffset));
#endif
		}
		else {
		  fm->push(totalOffset, newSize, _node, run->runOffset * data->clusterSize());
#if __WORDSIZE == 64
		  DEBUG(CRITICAL, "FM3.2 for offset 0x%lx push size 0x%lx at origin offset 0x%lx\n", totalOffset, newSize, run->runOffset * data->clusterSize());
#else
		  DEBUG(CRITICAL, "FM3.2 for offset 0x%llx push size 0x%llx at origin offset 0x%llx\n", totalOffset, newSize, run->runOffset * data->clusterSize());
#endif
		}
	      }
	    }
	    else { // shadow
	      fm->push(totalOffset, newSize, NULL, 0);
#if __WORDSIZE == 64
	      DEBUG(CRITICAL, "FM4.2 for offset 0x%lx push size 0x%lx as shadow (empty content)\n", totalOffset, newSize);
#else
	      DEBUG(CRITICAL, "FM4.2 for offset 0x%llx push size 0x%llx as shadow (empty content)\n", totalOffset, newSize);
#endif
	    }
	    
	    currentOffset += (run->runLength - registeredClusters) * data->clusterSize();
	    totalOffset += (run->runLength - registeredClusters) * data->clusterSize();
	    //currentOffset += (run->runLength) * data->clusterSize();
	    registeredClusters = run->runLength;
	    
	    currentRunIndex++;
	  }
	  //delete data;
	  DEBUG(CRITICAL, "\n");
	  //	  throw("yeah");
	  break;
	}
      }
    }
    ++iter;
  }
  externalData->close(); //XXX close the vfile ...
  delete externalData;
}


