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
 * TODO:
 *  - Deleted items : creation when MFT entry number differ but file-name
 *   and path are equal.
 *  - Directory indexes : deep search of deleted files event without content.
 *
 */

#include "ntfs.hpp"
#include "attributes/filename.hpp"
#include "attributes/attributelist.hpp"
#include "bitmapnode.hpp"

Ntfs::Ntfs() : mfso("ntfs")
{
  _rootOffset = 0;
  _orphan = NULL;
  _root = NULL;
  _mftDecode = -1;
  _indexDecode = -1;
  _unallocRootNode = NULL;
  try
    {
      DEBUG(INFO, "Constructor OK\n");
    }
  catch (std::exception & e)
    {
      std::cerr << "Ntfs::Ntfs() failed : could not build instance."
		<< e.what() << std::endl;
      if (_boot)
	delete _boot;
    }
}


Ntfs::~Ntfs()
{
  if (_mftMainFile)
    delete _mftMainFile;
}


void		Ntfs::_setMftMainFile(uint64_t mftEntryOffset)
{
  uint16_t	attributeNumber;

  Attribute	*attribute;

#if __WORDSIZE == 64
  DEBUG(INFO, "entry offset is 0x%lx\n", mftEntryOffset);
#else
  DEBUG(INFO, "entry offset is 0x%llx\n", mftEntryOffset);
#endif
  if (_mftEntry->decode(mftEntryOffset)) {
    //    _mftEntry->dumpHeader();
    attributeNumber = 0;

    while ((attribute = _mftEntry->getNextAttribute())) {
      attributeNumber++;
      DEBUG(INFO, "resident is 0x%x\n", attribute->attributeHeader()->nonResidentFlag);
      attribute->readHeader();
      if (attribute->getType() == ATTRIBUTE_DATA) {
	_mftMainFile->data(attribute);
      }
      else if (attribute->getType() == ATTRIBUTE_BITMAP) {
	_mftMainFile->bitmap(attribute);
      }
      else if (attribute->getType() == ATTRIBUTE_FILE_NAME) {
	_mftMainFile->fileName(attribute);
      }
      //      _mftEntry->dumpAttribute(attribute);
    }

    DEBUG(INFO, "Data has %u runs\n", _mftMainFile->data()->getRunListSize());
    DEBUG(INFO, "Bitmap has %u runs\n", _mftMainFile->bitmap()->getRunListSize());
  }
}


/**
 * Create a deleted node with its parent, not for an orphan node.
 */
void					Ntfs::_createDeletedWithParent(std::string fileNameS,
								       std::list<uint64_t> pathRefs,
								       uint32_t mftEntry,
								       AttributeFileName *fileName,
								       AttributeData *data, bool file,
								       AttributeStandardInformation *SI,
								       uint64_t offset)
{
  NtfsNode				*current = _root;
  std::list<uint64_t>::const_iterator	iter(pathRefs.begin());
  std::list<uint64_t>::const_iterator	listend(pathRefs.end());
  std::string				dirName;
  Attribute				*attribute;
  AttributeFileName			*metaFileName = NULL;
  AttributeStandardInformation		*metaSI = NULL;
  NtfsNode				*checkNode = NULL;
  uint32_t				parentId;
  NtfsNode				*newFile;
  MftEntry				*parent;

  /**
   * Iter every parents
   */
  while (iter != listend) {
    
    if (!(parent = _mftMainFile->get(*iter))) {
      break;
    }
    //      parent->dumpHeader();
    while ((attribute = parent->getNextAttribute())) {
      attribute->readHeader();
      if (attribute->getType() == ATTRIBUTE_FILE_NAME) {  
	/**
	 * Read parent directory name
	 */
	if (metaFileName != NULL) {
	  delete metaFileName;
	}
	metaFileName = new AttributeFileName(*attribute);
	
	if (metaFileName->data()->nameSpace & ATTRIBUTE_FN_NAMESPACE_WIN32 ||
	    metaFileName->data()->nameSpace == ATTRIBUTE_FN_NAMESPACE_POSIX) {
	  
	  dirName = metaFileName->getFileName();
	  DEBUG(INFO, "filename PARENT %s flags 0x%x\n", metaFileName->getFileName().c_str(), metaFileName->data()->flags);
	}
      }
      if (attribute->getType() == ATTRIBUTE_STANDARD_INFORMATION) {
	metaSI = new AttributeStandardInformation(*attribute);
      }
    }
    
    /**
     * Check if parent exists in current directory, create it if needed
     */  
    if ((checkNode = _ntfsNodeExists(dirName, current)) == NULL) {
#if __WORDSIZE == 64
      parentId = (*iter) & 0xffffffUL;
#else
      parentId = (*iter) & 0xffffffULL;
#endif
      _mftMainFile->entryDiscovered(parentId);
      current = new NtfsNode(dirName.c_str(), 0, current, this, false,
			     metaFileName, metaSI, parent, parentId,
			     _mftMainFile->data()->offsetFromID(parentId));
      //XXX	_mftMainFile->entryDiscovered(id);
      DEBUG(INFO, "creating %s as deleted\n", dirName.c_str());
      current->setDeleted();
    }
    else {
      current = checkNode;
    }
    ++iter;
    }
  
  DEBUG(INFO, "%s in %s\n", fileName->getFileName().c_str(), current->name().c_str());
  if (_ntfsNodeExists(fileNameS, current) == NULL ||
      !_mftMainFile->isEntryDiscovered(mftEntry)) {
    newFile = new NtfsNode(fileNameS, data->getSize(), current, this, file,
			   fileName, SI, _mftEntry, mftEntry, offset);
    DEBUG(INFO, "Created (usual) node : %s in %s\n", fileName->getFileName().c_str(), "tmp");
    newFile->node(_node);
    if (file) {
      newFile->data(data);
    }
    DEBUG(INFO, "creating %s as deleted in current2\n", fileName->getFileName().c_str());
    newFile->setDeleted();
  }
}


void	Ntfs::_createOrphanOrDeleted(std::string fileNameS,
				     AttributeFileName *fileName, bool file,
				     AttributeData *data, uint32_t mftEntry,
				     AttributeStandardInformation *SI,
				     uint64_t offset)
{
  uint64_t		parentRef = fileName->data()->parentDirectoryFileReference;
  //uint64_t		prevParentRef = 0;
  MftEntry		*parent = NULL;
  Attribute		*attribute;
  bool			orphan = false;
  std::list<uint64_t>	pathRefs;
  NtfsNode		*newFile;
  AttributeFileName	*metaFileName = NULL;

  std::set<uint64_t>		previousParent;
  /**
   * Create a list of parents
   */
  while ((parent = _mftMainFile->get(parentRef))) 
  {
    //    parent->dumpHeader();
//    if (prevParentRef == parentRef)
    if (previousParent.find(parentRef) != previousParent.end())
    {
      //XXX
      if (parent)
      {
        delete parent;
	parent = NULL;
      }
      break;
    }
    else 
    {
//      prevParentRef = parentRef;
      previousParent.insert(parentRef);
    }
    while ((attribute = parent->getNextAttribute())) 
    {
      attribute->readHeader();
      DEBUG(INFO, "type 0x%x\n", attribute->getType());

      if (attribute->getType() == ATTRIBUTE_FILE_NAME) 
      {
	metaFileName = new AttributeFileName(*attribute);
	
	DEBUG(INFO, "filename PARENT: %s\n", metaFileName->getFileName().c_str());
	DEBUG(INFO, "flags FN PARENT 0x%x\n", metaFileName->data()->flags);
	
	if (parentRef != NTFS_ROOT_DIR_PARENTREF) 
	{
#if __WORDSIZE == 64
	  DEBUG(INFO, "PUSHING 0x%lx\n", parentRef);
#else
	  DEBUG(INFO, "PUSHING 0x%llx\n", parentRef);
#endif
	  pathRefs.push_front(parentRef);
	}

	parentRef = metaFileName->data()->parentDirectoryFileReference;
	if (!(metaFileName->data()->flags & ATTRIBUTE_SI_FLAG_DIRECTORY)) 
	{
	  DEBUG(INFO, "\tIS NOT A DIRECTORY -> Orphan\n");
	  orphan = true;
	}
	if (metaFileName != NULL) 
	{
	  delete metaFileName;
	  metaFileName = NULL;
	}
	break;
      }
    }
    if (parent)
    {
      delete parent;
      parent = NULL;
    }
  }
  
  DEBUG(INFO, "over\n");
  /**
   * Create node if it is orphan
   */
  if (orphan) {
    if (!_orphan) {
      _orphan = new NtfsNode("$Orphans", 0, _root, this, false, NULL, SI, _mftEntry);
      _orphan->setDeleted();
    }
    if (_ntfsNodeExists(fileNameS, _orphan) == NULL || !_mftMainFile->isEntryDiscovered(mftEntry)) {
      newFile = new NtfsNode(fileNameS, data->getSize(), _orphan, this, true, fileName, SI, _mftEntry, mftEntry, offset);
      newFile->node(_node);
      newFile->data(data);
      DEBUG(INFO, "creating %s as deleted in orphans\n", fileName->getFileName().c_str());
      newFile->setDeleted();
    }
  }
  else {
    _createDeletedWithParent(fileNameS, pathRefs, mftEntry, fileName, data, file, SI, offset);
  }

  DEBUG(INFO, "Out from _createOrphanOrDeleted\n");
}


NtfsNode			*Ntfs::_ntfsNodeExists(std::string nodeName,
						       NtfsNode *parent)
{
  uint32_t			childCount = parent->childCount();
  uint32_t			i = 0;
  std::vector<class Node *>	children = parent->children();
  NtfsNode			*out = NULL;

  if (!nodeName.size()) {
    return NULL;
  }
  DEBUG(INFO, "childCount: %u\n", childCount);
  DEBUG(INFO, "parent is %s\n", parent->name().c_str());
  while (i != childCount && out == NULL) {
    DEBUG(VERBOSE, "checking for %s\n", children[i]->name().c_str());
    if (children[i]->name() == nodeName) {
      out = (NtfsNode *)children[i];
    }
    ++i;
  }
  return out;
}


/**
 * Search for files index/btree in entry
 */
uint32_t			Ntfs::_searchIndexesInEntry(uint64_t mftEntryDirOffset,
							    AttributeIndexRoot **indexRoot,
							    AttributeIndexAllocation **indexAllocation)
{
  Attribute			*attribute;
  AttributeAttributeList	*attributeList;
  uint32_t			indexRecordSize = 0;

  while ((attribute = _mftEntry->getNextAttribute())) {
    attribute->readHeader();
#if __WORDSIZE == 64
    DEBUG(INFO, "0x%lx\t\tattr @ 0x%x, type: 0x%x: %s, non resident: 0x%x, attribute length: 0x%x\n", mftEntryDirOffset, attribute->attributeOffset() - attribute->attributeHeader()->attributeLength, attribute->attributeHeader()->attributeTypeIdentifier, attribute->getName(attribute->attributeHeader()->attributeTypeIdentifier).c_str(), attribute->attributeHeader()->nonResidentFlag, attribute->attributeHeader()->attributeLength);
#else
    DEBUG(INFO, "0x%llx\t\tattr @ 0x%x, type: 0x%x: %s, non resident: 0x%x, attribute length: 0x%x\n", mftEntryDirOffset, attribute->attributeOffset() - attribute->attributeHeader()->attributeLength, attribute->attributeHeader()->attributeTypeIdentifier, attribute->getName(attribute->attributeHeader()->attributeTypeIdentifier).c_str(), attribute->attributeHeader()->nonResidentFlag, attribute->attributeHeader()->attributeLength);
#endif

    if (attribute->getType() == ATTRIBUTE_INDEX_ROOT) {
      (*indexRoot) = new AttributeIndexRoot(*attribute);
      DEBUG(INFO, "Index root stores attribute type 0x%x: %s\n", (*indexRoot)->data()->attributeInIndexType, attribute->getName((*indexRoot)->data()->attributeInIndexType).c_str());
      indexRecordSize = (*indexRoot)->indexRecordSizeBytes();
      (*indexRoot)->hasNext();
    }
    if (attribute->getType() == ATTRIBUTE_INDEX_ALLOCATION) {
      (*indexAllocation) = new AttributeIndexAllocation(*attribute);
      
#if __WORDSIZE == 64
      DEBUG(INFO, "0x%lx\tIndex allocation has %u runs\n", mftEntryDirOffset, (*indexAllocation)->getRunListSize());
#else
      DEBUG(INFO, "0x%llx\tIndex allocation has %u runs\n", mftEntryDirOffset, (*indexAllocation)->getRunListSize());
#endif
      //XXX case of multiple index_allocation ?
      break;
    }

    if (((*indexAllocation) == NULL || (*indexRoot) == NULL) && attribute->getType() == ATTRIBUTE_ATTRIBUTE_LIST) {
      uint32_t		externalIndexRoot;
      uint32_t		externalIndexAlloc;
      Attribute		*searchIndex;
      uint16_t		savedBufferOffset;
      uint16_t		savedAttributeOffset;

#if __WORDSIZE == 64
      DEBUG(CRITICAL, "Parsing for 0x%lx\n", mftEntryDirOffset);
#else
      DEBUG(CRITICAL, "Parsing for 0x%llx\n", mftEntryDirOffset);
#endif
      attributeList = new AttributeAttributeList(_vfile, *attribute);
      attributeList->setMftEntry(_mftMainFile->data()->idFromOffset(mftEntryDirOffset));
      externalIndexRoot = attributeList->getExternalAttributeIndexRoot();
      externalIndexAlloc = attributeList->getExternalAttributeIndexAlloc();

#if __WORDSIZE == 64
      DEBUG(CRITICAL, "index root is external and is mftentry %u (0x%x) offset 0x%lx\n", externalIndexRoot, externalIndexRoot, _mftMainFile->data()->offsetFromID(externalIndexRoot));
      DEBUG(CRITICAL, "index allocation is external and is mftentry %u (0x%x) offset 0x%lx\n", externalIndexAlloc, externalIndexAlloc, _mftMainFile->data()->offsetFromID(externalIndexAlloc));
#else
      DEBUG(CRITICAL, "index root is external and is mftentry %u (0x%x) offset 0x%llx\n", externalIndexRoot, externalIndexRoot, _mftMainFile->data()->offsetFromID(externalIndexRoot));
      DEBUG(CRITICAL, "index allocation is external and is mftentry %u (0x%x) offset 0x%llx\n", externalIndexAlloc, externalIndexAlloc, _mftMainFile->data()->offsetFromID(externalIndexAlloc));
#endif
      if (externalIndexRoot) {

	savedBufferOffset = _mftEntry->bufferOffset();
	savedAttributeOffset = _mftEntry->attributeOffset();

	if (_mftEntry->decode(_mftMainFile->data()->offsetFromID(externalIndexRoot))) {
	  while ((searchIndex = _mftEntry->getNextAttribute())) {
	    searchIndex->readHeader();
	    if (searchIndex->getType() == ATTRIBUTE_INDEX_ROOT) {
	      (*indexRoot) = new AttributeIndexRoot(*searchIndex);
	    }
	  }
	}

	// Resync _mftEntry to the one used in _parseDirTree
	_mftEntry->decode(mftEntryDirOffset);
	_mftEntry->continueAt(savedBufferOffset, savedAttributeOffset);

      }
      if (externalIndexAlloc) {

	savedBufferOffset = _mftEntry->bufferOffset();
	savedAttributeOffset = _mftEntry->attributeOffset();

	if (_mftEntry->decode(_mftMainFile->data()->offsetFromID(externalIndexAlloc))) {
	  while ((searchIndex = _mftEntry->getNextAttribute())) {
	    searchIndex->readHeader();
	    if (searchIndex->getType() == ATTRIBUTE_INDEX_ALLOCATION) {
	      (*indexAllocation) = new AttributeIndexAllocation(*searchIndex);
	    }
	  }
	}

	// Resync _mftEntry to the one used in _parseDirTree
	_mftEntry->decode(mftEntryDirOffset);
	_mftEntry->continueAt(savedBufferOffset, savedAttributeOffset);

      }
    }
    DEBUG(INFO, "trying to read next attribute\n");
  }

  return indexRecordSize;
}


void	Ntfs::_initTreeWalk(AttributeIndexRoot *indexRoot,
			    AttributeIndexAllocation *indexAllocation,
			    uint32_t indexRecordSize, uint32_t *entryOffset,
			    uint32_t *relOffsetEndUsed)
{
  if (indexAllocation) {
    indexAllocation->fillRecords(_boot->getBootBlock()->bytePerSector,
				 _boot->clusterSize(), indexRecordSize);
#if __WORDSIZE == 64
    DEBUG(INFO, "Reading 0x%x bytes IndexAllocation @ 0x%lx\n", indexAllocation->indexRecordSize(), indexAllocation->realOffset());
#else
    DEBUG(INFO, "Reading 0x%x bytes IndexAllocation @ 0x%llx\n", indexAllocation->indexRecordSize(), indexAllocation->realOffset());
#endif
    
    if (indexRoot->currentEntryLength()) {
      (*entryOffset) = indexRoot->currentEntryOffset();
      (*relOffsetEndUsed) = indexRoot->nodeHeader()->relOffsetEndUsed;	  
    }
    else {
      (*entryOffset) = indexAllocation->getEntryOffset();
      if (indexAllocation->getNodeHeader()) {
	(*relOffsetEndUsed) = indexAllocation->getNodeHeader()->relOffsetEndUsed;
      }
      else {
	(*relOffsetEndUsed) = (*entryOffset);
      }
    }
    if ((*entryOffset) == 0) {
      DEBUG(INFO, "0\n");
      return ;
    }
    DEBUG(INFO, "with indexAlloc entryOffset 0x%x offsetEnd 0x%x\n", (*entryOffset), (*relOffsetEndUsed));
  }
  else {
    (*entryOffset) = indexRoot->currentEntryOffset();
    (*relOffsetEndUsed) = indexRoot->nodeHeader()->relOffsetEndUsed;
    DEBUG(INFO, "with only indexRoot entryOffset 0x%x offsetEnd 0x%x\n", (*entryOffset), (*relOffsetEndUsed));
  }  
}


void	Ntfs::_updateTreeWalk(AttributeIndexRoot *indexRoot,
			      AttributeIndexAllocation *indexAllocation,
			      uint32_t *entryOffset,
			      uint32_t *relOffsetEndUsed, bool *indexRootOver)
{
  if (indexAllocation) {
    if (indexRoot->hasNext() && indexRoot->currentEntryLength()) {
      (*entryOffset) = indexRoot->currentEntryOffset();
    }
    else {
      (*indexRootOver) = true;
      (*entryOffset) = indexAllocation->getEntryOffset();
      if (indexAllocation->getNodeHeader()) {
	(*relOffsetEndUsed) = indexAllocation->getNodeHeader()->relOffsetEndUsed;
      }
      else {
	(*relOffsetEndUsed) = (*entryOffset);
      }
      if ((*entryOffset) >= (*relOffsetEndUsed)) {
	;
#if __WORDSIZE == 64
	DEBUG(INFO, "end of indexalloc\n");
#else
	DEBUG(INFO, "end of indexalloc\n");
#endif
      }
    }
    DEBUG(INFO, "current 0x%x end 0x%x\n", (*entryOffset), (*relOffsetEndUsed));
  }
  else {
    if (indexRoot->hasNext()) {
      (*entryOffset) = indexRoot->currentEntryOffset();
    }
    else {
      (*entryOffset) = (*relOffsetEndUsed);
    }
  }
}

NtfsNode			*Ntfs::_createRegularADSNodes(uint64_t offset,
							      uint32_t adsAmount,
							      uint32_t mftID,
							      AttributeStandardInformation *metaSI,
							      Node *currentDir,
							      AttributeFileName *metaFName)
{
  AttributeData			**data = new AttributeData *[adsAmount];
  uint32_t			iADS = 0;
  Attribute			*attribute;
  AttributeAttributeList	*attributeList = NULL;
  uint32_t			extAttrData;
  NtfsNode			*returnNode = NULL;

  _mftEntry->decode(offset);
  while ((attribute = _mftEntry->getNextAttribute())) 
  {
    attribute->readHeader();
    if (attribute->getType() == ATTRIBUTE_DATA) 
    {
      data[iADS] = new AttributeData(*attribute);
      if (!data[iADS]->attributeHeader()->nonResidentFlag) 
      {
	data[iADS]->offset(data[iADS]->getOffset() + offset + data[iADS]->attributeOffset());
      }
      iADS++;
    }
    if (attribute->getType() == ATTRIBUTE_ATTRIBUTE_LIST) 
    {
      attributeList = new AttributeAttributeList(_vfile, *attribute);
      attributeList->setMftEntry(mftID);
    }
  }

  if (attributeList) 
  {
    extAttrData = attributeList->getExternalAttributeData();
    if (extAttrData && _mftEntry->decode(_mftMainFile->data()->offsetFromID(extAttrData))) 
     {
      while ((attribute = _mftEntry->getNextAttribute())) 
      {
	attribute->readHeader();
	if (attribute->getType() == ATTRIBUTE_DATA) 
	{
	  data[iADS] = new AttributeData(*attribute);
	  if (!data[iADS]->attributeHeader()->nonResidentFlag) 
	  {
	    data[iADS]->offset(data[iADS]->getOffset() + offset + data[iADS]->attributeOffset());
	  }
	  iADS++;
	}
      }
    }
  }

  for (iADS = 0; iADS < adsAmount; iADS++) {
    std::ostringstream	name;

    name << metaFName->getFileName() << data[iADS]->getExtName();
    returnNode = new NtfsNode(name.str(), data[iADS]->getSize(), currentDir, this,
			      true, metaFName, metaSI, _mftEntry, mftID,
			      offset);
    returnNode->node(_node);
    returnNode->data(data[iADS]);
  }

  return returnNode;
}

void				Ntfs::_createRegularNode(Node *currentDir,
							 uint32_t dirMftEntry,
							 uint64_t offset,
							 uint32_t curMftEntry)
{
  Attribute			*attribute;
  AttributeAttributeList	*attributeList = NULL;
  AttributeFileName		*fullFileName = NULL;
  AttributeFileName		*metaFileName = NULL;
  AttributeStandardInformation	*metaSI = NULL;
  AttributeData			*data = new AttributeData();
  uint8_t			fileType = 0;
  uint64_t			size = 0;
  uint32_t			extAttrData;
  NtfsNode			*newNode = NULL;
  uint32_t			ads = 0;
  std::list<uint64_t>		dataOffsets;

  while ((attribute = _mftEntry->getNextAttribute())) {
    attribute->readHeader();
#if __WORDSIZE == 64
    DEBUG(INFO, "\tattr @ 0x%x, type: 0x%x: %s, non resident: 0x%x, attribute length: 0x%x\n", attribute->attributeOffset(), attribute->attributeHeader()->attributeTypeIdentifier, attribute->getName(attribute->attributeHeader()->attributeTypeIdentifier).c_str(), attribute->attributeHeader()->nonResidentFlag, attribute->attributeHeader()->attributeLength);
#else
    DEBUG(INFO, "\tattr @ 0x%x, type: 0x%x: %s, non resident: 0x%x, attribute length: 0x%x\n", attribute->attributeOffset(), attribute->attributeHeader()->attributeTypeIdentifier, attribute->getName(attribute->attributeHeader()->attributeTypeIdentifier).c_str(), attribute->attributeHeader()->nonResidentFlag, attribute->attributeHeader()->attributeLength);
#endif
    if (attribute->getType() == ATTRIBUTE_STANDARD_INFORMATION) {
      metaSI = new AttributeStandardInformation(*attribute);
      if (metaSI->data()->flags & ATTRIBUTE_SI_FLAG_DIRECTORY) {
	DEBUG(INFO, "setting dir\n");
	fileType = 2;
      }
      else if (metaSI->data()->flags & ATTRIBUTE_SI_FLAG_SYSTEM ||
	       metaSI->data()->flags & ATTRIBUTE_SI_FLAG_ARCHIVE) {
	DEBUG(INFO, "setting file\n");
	fileType = 1;
      }
    }
    if (attribute->getType() == ATTRIBUTE_FILE_NAME) {
      metaFileName = new AttributeFileName(*attribute);
      if (metaFileName->data()->nameSpace & ATTRIBUTE_FN_NAMESPACE_WIN32 ||
	  metaFileName->data()->nameSpace == ATTRIBUTE_FN_NAMESPACE_POSIX) {
#if __WORDSIZE == 64
	if ((metaFileName->data()->parentDirectoryFileReference & 0xffffffUL) == dirMftEntry)
#else
	if ((metaFileName->data()->parentDirectoryFileReference & 0xffffffULL) == dirMftEntry)
#endif
	  {
	    fullFileName = metaFileName;
	  }
	if (metaFileName->data()->flags & ATTRIBUTE_SI_FLAG_DIRECTORY) {
	  DEBUG(INFO, "setting dir\n");
	  fileType = 2;
	}
	else if (metaFileName->data()->flags & ATTRIBUTE_SI_FLAG_SYSTEM ||
		 metaFileName->data()->flags & ATTRIBUTE_SI_FLAG_ARCHIVE) {
	  DEBUG(INFO, "setting file\n");
	  fileType = 1;
	}
	if (!size) {
	  size = metaFileName->data()->realSizeOfFile;
#if __WORDSIZE == 64
	  DEBUG(INFO, "size from filename %lu\n", size);
	  DEBUG(INFO, "size from data attr %lu\n", metaFileName->data()->allocatedSizeOfFile);
#else
	  DEBUG(INFO, "size from filename %llu\n", size);
	  DEBUG(INFO, "size from data attr %llu\n", metaFileName->data()->allocatedSizeOfFile);
#endif
	}
	DEBUG(INFO, "filename is %s\n", metaFileName->getFileName().c_str());
      }
    }
    if (attribute->getType() == ATTRIBUTE_DATA) {
      // XXX delete previous data ?
      data = new AttributeData(*attribute);
      if (!size) {
	size = data->getSize();
      }
      if (!data->attributeHeader()->nonResidentFlag) {
	data->offset(data->getOffset() + offset + data->attributeOffset());
      }
      ads++;
    }
    if (attribute->getType() == ATTRIBUTE_ATTRIBUTE_LIST) {
      attributeList = new AttributeAttributeList(_vfile, *attribute);
      attributeList->setMftEntry(curMftEntry);
    }
  }

#if __WORDSIZE == 64
  DEBUG(INFO, "data size before %lu size is %lu\n", data->getSize(), size);
#else
  DEBUG(INFO, "data size before %llu sise is %llu\n", data->getSize(), size);
#endif
  if (attributeList && (fileType == 1) && !data->getOffset()) {
    while ((extAttrData = attributeList->getExternalAttributeData())) {
      // Fetch every offsets of external $DATA attributes
      if (extAttrData) {
	dataOffsets.push_back(_mftMainFile->data()->offsetFromID(extAttrData));
#if __WORDSIZE == 64
 	DEBUG(INFO, "External attrdata: 0x%x @ size: 0x%x latest addr pushed: 0x%lx\n", extAttrData, (uint32_t)dataOffsets.size(), dataOffsets.back());
#else
 	DEBUG(INFO, "External attrdata: 0x%x @ size: 0x%x latest addr pushed: 0x%llx\n", extAttrData, (uint32_t)dataOffsets.size(), dataOffsets.back());
#endif
      }
    }

    if (dataOffsets.size()) {
      if (_mftEntry->decode(dataOffsets.front())) {
	// Set data from the first $DATA attribute
	while ((attribute = _mftEntry->getNextAttribute())) {
	  attribute->readHeader();
	  if (attribute->getType() == ATTRIBUTE_DATA) {
	    data = new AttributeData(*attribute);
	    if (!data->attributeHeader()->nonResidentFlag) {
	      data->offset(data->getOffset() + offset + data->attributeOffset());
	    }
	    if (!size && data->attributeHeader()->nonResidentFlag) {
	      // Here we assume this first external $DATA attr holds real size of file !
	      size = data->nonResidentDataHeader()->attributeContentActualSize;
#if __WORDSIZE == 64
	      DEBUG(INFO, "sizes from external attr $DATA are: %lu (alloc), %lu (actual), %lu (init)\n", data->nonResidentDataHeader()->attributeContentAllocatedSize, data->nonResidentDataHeader()->attributeContentActualSize, data->nonResidentDataHeader()->attributeContentInitializedSize);
#else
	      DEBUG(INFO, "sizes from external attr $DATA are: %llu (alloc), %llu (actual), %llu (init)\n", data->nonResidentDataHeader()->attributeContentAllocatedSize, data->nonResidentDataHeader()->attributeContentActualSize, data->nonResidentDataHeader()->attributeContentInitializedSize);
#endif
	    }
	    ads++;
	  }
	}
      }
    }
  }


#if __WORDSIZE == 64
  DEBUG(INFO, "data size after %lu\n", data->getSize());
#else
  DEBUG(INFO, "data size after %llu\n", data->getSize());
#endif
  
  if (fullFileName) {
#if __WORDSIZE == 64
    DEBUG(INFO, "\t\tmftentry %u about to create %s offset 0x%lx\n", curMftEntry, fullFileName->getFileName().c_str(), offset);
#else
    DEBUG(INFO, "\t\tmftentry %u about to create %s offset 0x%llx\n", curMftEntry, fullFileName->getFileName().c_str(), offset);
#endif
    
    if (curMftEntry != NTFS_ROOT_DIR_MFTENTRY) {
      if (ads <= 1) {
	newNode = new NtfsNode(fullFileName->getFileName().c_str(),
			       data->getSize(), currentDir, this, (fileType == 1),
			       fullFileName, metaSI, _mftEntry, curMftEntry,
			       offset);
	newNode->node(_node);
	if (fileType == 1 && newNode) {
	  newNode->data(data);
	  if (dataOffsets.size() > 1) {
	    newNode->dataOffsets(dataOffsets);
	  }
	}
      }
      else {
	// XXX Case of heavy fragmented file + ADS ignored
	newNode = _createRegularADSNodes(offset, ads, curMftEntry, metaSI, currentDir, fullFileName);
      }
	
      std::vector<Node *>	newVector;
      newVector.push_back(newNode);
      _mftEntryToNode.insert(std::pair<uint32_t, std::vector<Node *> >(curMftEntry, newVector));
      
    }
    
    if (fileType == 2 && curMftEntry != NTFS_ROOT_DIR_MFTENTRY && newNode) {
#if __WORDSIZE == 64
      DEBUG(INFO, "\t\tcreate dir %s mftentry %u offset 0x%lx\n", fullFileName->getFileName().c_str(), curMftEntry, offset);
#else
      DEBUG(INFO, "\t\tcreate dir %s mftentry %u offset 0x%llx\n", fullFileName->getFileName().c_str(), curMftEntry, offset);
#endif
      _parseDirTree(newNode, curMftEntry, offset);
    }
  }
}


void				Ntfs::_createLinkedNode(Node *currentDir,
							uint32_t dirMftEntry,
							uint32_t curMftEntry)
{
  Attribute			*attribute;
  std::vector<Node *>::iterator	it = _mftEntryToNode[curMftEntry].begin();
  AttributeFileName		*metaFileName = NULL;
  AttributeFileName		*fullFileName = NULL;
  uint64_t			offset;
  AttributeAttributeList	*attrList = NULL;
  uint32_t			externalFileName = 0;

  while (it != _mftEntryToNode[curMftEntry].end()) {
    if (currentDir == (*it)->parent()) {
      DEBUG(INFO, "%u already discovered\n", curMftEntry);
      return ;
    }
    else {
      DEBUG(INFO, "%u already discovered in node %s discovered as link in %s\n", curMftEntry, currentDir->name().c_str(), (*it)->parent()->name().c_str());
      ;
    }
    it++;
  }
  
  if (_mftEntryToNode[curMftEntry].size()) {
    DEBUG(INFO, "%u searching real filename\n", curMftEntry);
    
    if ((offset = _mftMainFile->data()->offsetFromID(curMftEntry))) {
#if __WORDSIZE == 64
      DEBUG(INFO, "%u offset is 0x%lx\n", curMftEntry, offset);
#else
      DEBUG(INFO, "%u offset is 0x%llx\n", curMftEntry, offset);
#endif		
      _mftEntry->decode(offset);
      
      while ((attribute = _mftEntry->getNextAttribute())) {
	DEBUG(INFO, "%u attribute\n", curMftEntry);
	attribute->readHeader();
	if (attribute->getType() == ATTRIBUTE_FILE_NAME) {
	  metaFileName = new AttributeFileName(*attribute);
	  if (metaFileName->data()->nameSpace & ATTRIBUTE_FN_NAMESPACE_WIN32 ||
	      metaFileName->data()->nameSpace == ATTRIBUTE_FN_NAMESPACE_POSIX) {
	    DEBUG(INFO, "%u filename %s\n", curMftEntry, metaFileName->getFileName().c_str());
#if __WORDSIZE == 64
	    if ((metaFileName->data()->parentDirectoryFileReference & 0xffffffUL) == dirMftEntry)
#else
	    if ((metaFileName->data()->parentDirectoryFileReference & 0xffffffULL) == dirMftEntry)
#endif
	      {
		fullFileName = metaFileName;
		break;
	      }
	  }
	}
	if (attribute->getType() == ATTRIBUTE_ATTRIBUTE_LIST) {
	  attrList = new AttributeAttributeList(_vfile, *attribute);
	  attrList->setMftEntry(curMftEntry);
	}
      }

      if (attrList && !fullFileName) {
	while ((externalFileName = attrList->getExternalAttributeFileName())) {
	  DEBUG(INFO, "got %u\n", externalFileName);
	  if (_mftEntry->decode(_mftMainFile->data()->offsetFromID(externalFileName))) {
	    // XXX no need to resync _mftEntry ?
	    while ((attribute = _mftEntry->getNextAttribute())) {
	      DEBUG(INFO, "reading\n");
	      attribute->readHeader();
	      if (attribute->getType() == ATTRIBUTE_FILE_NAME) {
		metaFileName = new AttributeFileName(*attribute);
		if (metaFileName->data()->nameSpace & ATTRIBUTE_FN_NAMESPACE_WIN32 ||
		    metaFileName->data()->nameSpace == ATTRIBUTE_FN_NAMESPACE_POSIX) {
		  DEBUG(INFO, "%u filename %s\n", curMftEntry, metaFileName->getFileName().c_str());
#if __WORDSIZE == 64
		  if ((metaFileName->data()->parentDirectoryFileReference & 0xffffffUL) == dirMftEntry)
#else
		  if ((metaFileName->data()->parentDirectoryFileReference & 0xffffffULL) == dirMftEntry)
#endif
		    {
		      fullFileName = metaFileName;
		      break;
		    }
		}
	      }
	    }
	  }
	}
      }
    }
  }
  
  if (fullFileName) {
    VLink	*newLink = new VLink(_mftEntryToNode[curMftEntry][0], currentDir, fullFileName->getFileName().c_str());
    DEBUG(INFO, "link created for mft #%u with name %s\n", curMftEntry, fullFileName->getFileName().c_str());
    _mftEntryToNode[curMftEntry].push_back(newLink);
  }
}

void				Ntfs::_parseDirTree(Node *currentDir,
						    uint32_t dirMftEntry,
						    uint64_t mftEntryDirOffset)
{
  AttributeIndexRoot		*indexRoot = NULL;
  AttributeIndexAllocation	*indexAllocation = NULL;
  uint32_t			indexRecordSize;
  uint32_t			entryOffset;
  uint32_t			relOffsetEndUsed;
  uint32_t			curMftEntry;
  bool				indexRootOver = false;
  uint64_t			offset;
  uint32_t			prevEntryOffset = 0;

#if __WORDSIZE == 64
  DEBUG(INFO, "0x%lx\tParsedir tree beginning\n", mftEntryDirOffset);
#else
  DEBUG(INFO, "0x%llx\tParsedir tree beginning\n", mftEntryDirOffset);
#endif
  if (!_mftEntry->decode(mftEntryDirOffset)) {
    return;
  }

  /**
   * Search for files index/btree in _mftEntry
   */
  indexRecordSize = _searchIndexesInEntry(mftEntryDirOffset, &indexRoot, &indexAllocation);


  DEBUG(INFO, "Indexes search done.\n");
  if (!indexRoot) {
    return ;
  }
  if (indexAllocation == NULL && indexRoot != NULL && indexRoot->nodeHeader()->flags == ENTRY_CHILD_NODE_EXIST) {
    return ;
  }
  if (indexRoot->data()->attributeInIndexType != ATTRIBUTE_FILE_NAME ||
      (!indexRoot->entriesAmount() && indexAllocation == NULL)) {
    return ;
  }

  /**
   * Set indexes depending of attributes discovered
   */
  _initTreeWalk(indexRoot, indexAllocation, indexRecordSize, &entryOffset,
		&relOffsetEndUsed);


#if __WORDSIZE == 64
  DEBUG(INFO, "Next entry is at 0x%x, amount of entries in indexRoot %u\n", entryOffset, indexRoot->entriesAmount());
#else
  DEBUG(INFO, "Next entry is at 0x%x, amount of entries in indexRoot %u\n", entryOffset, indexRoot->entriesAmount());
#endif    
    
  /**
   * Iter every valid files index
   */
  while (entryOffset < relOffsetEndUsed) {

    // Get next file entry to create from tree
    if (indexAllocation) {
      if (!indexRootOver) {
	curMftEntry = indexRoot->nextMftEntry();
      }
      else {
	curMftEntry = indexAllocation->readNextIndex();
      }
    }
    else {
      curMftEntry = indexRoot->nextMftEntry();
    }

    if (curMftEntry == 0 && prevEntryOffset == entryOffset) {
      break;
    }
#if __WORDSIZE == 64
    DEBUG(INFO, "0x%lx\tcurrent 0x%x end 0x%x mft# %u length entry %u\n", mftEntryDirOffset, entryOffset, relOffsetEndUsed, curMftEntry, indexRoot->currentEntryLength());
#else
    DEBUG(INFO, "0x%llx\tcurrent 0x%x end 0x%x mft# %u\n", mftEntryDirOffset, entryOffset, relOffsetEndUsed, curMftEntry);
#endif

    if (!(_mftMainFile->isEntryDiscovered(curMftEntry)) && curMftEntry < _mftMainFile->getNumberOfRecords()) {
      _mftMainFile->entryDiscovered(curMftEntry);
      _setStateInfo(_mftMainFile->discoverPercent());  
      if ((offset = _mftMainFile->data()->offsetFromID(curMftEntry))) {	
	if (_mftEntry->decode(offset)) {
	  /**
	   * Entry is valid and has never been discovered.
	   * Create file or dir and recurse if needed.
	   */
	  _createRegularNode(currentDir, dirMftEntry, offset, curMftEntry);

	}
      }
    }

    else if (curMftEntry && curMftEntry < _mftMainFile->getNumberOfRecords()) {
      /**
       * Entry can already be discovered but sit in an other directory.
       * Create link.
       */
      _createLinkedNode(currentDir, dirMftEntry, curMftEntry);
    }
    
    prevEntryOffset = entryOffset;

    _updateTreeWalk(indexRoot, indexAllocation, &entryOffset,
		    &relOffsetEndUsed, &indexRootOver);
    
#if __WORDSIZE == 64
    DEBUG(INFO, "0x%lx\tend of loop current 0x%x end 0x%x mft# %u\n", mftEntryDirOffset, entryOffset, relOffsetEndUsed, curMftEntry);
#else
    DEBUG(INFO, "0x%llx\tend of loop current 0x%x end 0x%x mft# %u\n", mftEntryDirOffset, entryOffset, relOffsetEndUsed, curMftEntry);
#endif
  }

  DEBUG(INFO, "loop...\n");
  //_mftMainFile->dumpDiscoveredEntries();
}


void		Ntfs::_walkMftMainFile()
{
  std::string	filename;
  uint64_t	rootDirOffset;

  DEBUG(INFO, "totalRecords: %u\n", _mftMainFile->getNumberOfRecords());

  rootDirOffset = _mftMainFile->data()->offsetFromID(NTFS_ROOT_DIR_MFTENTRY);
#if __WORDSIZE == 64
  DEBUG(INFO, "Root directory offset is 0x%lx\n", rootDirOffset);
#else
  DEBUG(INFO, "Root directory offset is 0x%llx\n", rootDirOffset);
#endif

  /**
   * Here we can set offset of a directory to recurse in
   */
  _parseDirTree(_root, NTFS_ROOT_DIR_MFTENTRY, rootDirOffset);
}

void		Ntfs::_setRootDirectory(uint64_t mftEntryOffset)
{
  Attribute	*attribute;

#if __WORDSIZE == 64
  DEBUG(INFO, "root directory mftentry is @0x%lx\n", mftEntryOffset);
#else
  DEBUG(INFO, "root directory mftentry is @0x%llx\n", mftEntryOffset);
#endif

  if (_mftEntry->decode(mftEntryOffset)) {
    //    _mftEntry->dumpHeader();

    /**
     * Set root entry meta data
     */
    while ((attribute = _mftEntry->getNextAttribute())) {
      attribute->readHeader();

      if (attribute->getType() == ATTRIBUTE_STANDARD_INFORMATION) {
	_rootDirectory->standardInformation(attribute);
      }
      else if (attribute->getType() == ATTRIBUTE_FILE_NAME) {
	_rootDirectory->fileName(attribute);
      }
      else if (attribute->getType() == ATTRIBUTE_SECURITY_DESCRIPTOR) {
	_rootDirectory->securityDescriptor(attribute);
      }
      else if (attribute->getType() == ATTRIBUTE_INDEX_ROOT) {
	_rootDirectory->indexRoot(attribute);
      }
      else if (attribute->getType() == ATTRIBUTE_INDEX_ALLOCATION) {
	_rootDirectory->indexAllocation(attribute);
      }
    }
    DEBUG(INFO, "Index allocation has %u runs\n", _rootDirectory->indexAllocation()->getRunListSize());
    
    std::ostringstream	filename;

    _rootDirectory->indexAllocation()->fillRecords(_boot->getBootBlock()->bytePerSector, _boot->clusterSize(), _rootDirectory->indexRoot()->indexRecordSizeBytes()); \

    while (_rootDirectory->indexRoot()->hasNext()) {
      _rootDirectory->indexAllocation()->readNextIndex();
    }
  }
}

void				Ntfs::_deletedNodeWithADS(uint64_t offset,
							  uint32_t adsAmount,
							  uint32_t mftID,
							  AttributeStandardInformation *metaSI)
{
  Attribute			*attribute;
  AttributeFileName		*metaFileName = NULL;
  AttributeFileName		*fullFileName = NULL;
  AttributeData			**data = new AttributeData *[adsAmount];
  uint8_t			fileType = 0;
  uint64_t			size = 0;
  uint32_t			iADS = 0;
  
  _mftEntry->decode(offset);
  while ((attribute = _mftEntry->getNextAttribute())) {
    attribute->readHeader();
    if (attribute->getType() == ATTRIBUTE_FILE_NAME) {
      metaFileName = new AttributeFileName(*attribute);
      if (metaFileName->data()->nameSpace & ATTRIBUTE_FN_NAMESPACE_WIN32 ||
	  metaFileName->data()->nameSpace == ATTRIBUTE_FN_NAMESPACE_POSIX) {
	fullFileName = metaFileName;
      }
      if (metaFileName->data()->nameSpace & ATTRIBUTE_FN_NAMESPACE_WIN32 ||
	  metaFileName->data()->nameSpace & ATTRIBUTE_FN_NAMESPACE_POSIX) {
	if (metaFileName->data()->flags & ATTRIBUTE_SI_FLAG_SYSTEM ||
	    metaFileName->data()->flags & ATTRIBUTE_SI_FLAG_ARCHIVE) {
	  fileType = 1;
	}
      }
      if (!size)
	size = metaFileName->data()->realSizeOfFile;
    }
    if (attribute->getType() == ATTRIBUTE_DATA) {
      data[iADS] = new AttributeData(*attribute);
      if (!size)
	size = data[iADS]->getSize();
      if (!data[iADS]->attributeHeader()->nonResidentFlag)
	data[iADS]->offset(data[iADS]->getOffset() + offset + data[iADS]->attributeOffset());
      iADS++;
    }
  }
  
  for (iADS = 0; iADS < adsAmount; iADS++) {
    std::ostringstream	name;

	if (fullFileName != NULL){
		// XXX Added by jmo in order to avoid Segfault when fullFileName == 0
		name << fullFileName->getFileName() << data[iADS]->getExtName();
		_createOrphanOrDeleted(name.str(), fullFileName, true, data[iADS], mftID, metaSI, offset);
	}
  }
  //done before: _setStateInfo(_mftMainFile->discoverPercent());
}

void					Ntfs::_checkOrphanEntries()
{
  std::map<uint32_t, bool>		entryMap = _mftMainFile->getEntryMap();
  std::map<uint32_t, bool>::iterator	it = entryMap.begin();
  uint64_t				offset;
  Attribute				*attribute;
  uint32_t				i = 0;
  uint32_t				mftAmountOfRecords = _mftMainFile->getNumberOfRecords();

  while (i < mftAmountOfRecords) {
    if (it == entryMap.end() || i != it->first) {
      DEBUG(INFO, "Checking id 0x%x\n", i);
      _mftMainFile->entryDiscovered(i);
      if ((offset = _mftMainFile->data()->offsetFromID(i))) {
	DEBUG(INFO, "Parsing id 0x%x\n", i);
	if (_mftEntry->decode(offset)) {
	  AttributeFileName		*metaFileName = NULL;
	  AttributeFileName		*fullFileName = NULL;
	  AttributeStandardInformation	*metaSI = NULL;
	  AttributeData			*data = new AttributeData();
	  uint8_t			fileType = 0;
	  uint64_t			size = 0;
	  uint32_t			ads = 0;
	  
#if __WORDSIZE == 64
	  DEBUG(INFO, "Offset is 0x%lx\n", offset);
#else
	  DEBUG(INFO, "Offset is 0x%llx\n", offset);
#endif
	  while ((attribute = _mftEntry->getNextAttribute())) {
	    attribute->readHeader();
	    if (attribute->getType() == ATTRIBUTE_STANDARD_INFORMATION) {
	      metaSI = new AttributeStandardInformation(*attribute);
	    }
	    if (attribute->getType() == ATTRIBUTE_FILE_NAME) {
	      metaFileName = new AttributeFileName(*attribute);
	      if (metaFileName->data()->nameSpace & ATTRIBUTE_FN_NAMESPACE_WIN32 ||
		  metaFileName->data()->nameSpace == ATTRIBUTE_FN_NAMESPACE_POSIX) {
		fullFileName = metaFileName;
	      }
	      if (metaFileName->data()->flags & ATTRIBUTE_SI_FLAG_DIRECTORY) {
		fileType = 2;
	      }
	      else if (metaFileName->data()->nameSpace & ATTRIBUTE_FN_NAMESPACE_WIN32 ||
		  metaFileName->data()->nameSpace & ATTRIBUTE_FN_NAMESPACE_POSIX) {
		if (metaFileName->data()->flags & ATTRIBUTE_SI_FLAG_SYSTEM ||
		    metaFileName->data()->flags & ATTRIBUTE_SI_FLAG_ARCHIVE) {
		  fileType = 1;
		}
	      }
	      if (!size)
		size = metaFileName->data()->realSizeOfFile;
	    }
	    if (attribute->getType() == ATTRIBUTE_DATA) {
	      data = new AttributeData(*attribute);
	      if (!size)
		size = data->getSize();
	      if (!data->attributeHeader()->nonResidentFlag)
		data->offset(data->getOffset() + offset + data->attributeOffset());
	      ads++;
	    }
	  }
	 
	  if (ads <= 1) {
	    if (fileType == 1 && fullFileName) {
	      _createOrphanOrDeleted(fullFileName->getFileName(), fullFileName,
				     true, data, i, metaSI, offset);
	      _setStateInfo(_mftMainFile->discoverPercent());
	    }
	    else if (fileType == 2 && fullFileName) {
	      _createOrphanOrDeleted(fullFileName->getFileName(), fullFileName,
				     false, data, i, metaSI, offset);
	      _setStateInfo(_mftMainFile->discoverPercent());
	    }
	  }
	  // FIXME metaSI can be null ?
	  else if (metaSI) {
	    _deletedNodeWithADS(offset, ads, i, metaSI);
	  }
	}
      }
    }
    if (it != entryMap.end() && i == it->first) {
	  DEBUG(INFO, "inc it\n");
      it++;
    }
    i++;
  }
  //_mftMainFile->dumpDiscoveredEntries();
}

/**
 * Read the $Bitmap FS top-level metafile create nodes made of unallocated
 * space if "bitmap-parse" argument is true.
 *  - Searches for $Bitmap file with MFT entry number 6.
 *  - Reads $Bitmap content.
 *  - Fills the unallocated top-level node directory with one node file for
 *  each unallocated cluster chunk.
 */
void		Ntfs::_readBitmap()
{
  std::string			nodeName = std::string("$Bitmap");
  uint32_t			childCount = _root->childCount();
  uint32_t			i = 0;
  std::vector<class Node *>	children = _root->children();
  NtfsNode			*bitmap = NULL;
  VFile				*vfile;
  uint8_t			*data;
  Node				*unallocatedByAddresses = NULL;
  uint8_t			bit;
  uint64_t			clusterIndex = 0;
  uint64_t			unallocChunkStart = 0;
  bool				inUnalloc = false;

  // Gets the $Bitmap metafile
  if (!nodeName.size()) {
    return ;
  }
  DEBUG(CRITICAL, "childCount: %u\n", childCount);
  DEBUG(CRITICAL, "parent is %s\n", _root->name().c_str());
  while (i != childCount && bitmap == NULL) {
    DEBUG(VERBOSE, "checking for %s\n", children[i]->name().c_str());
    if (children[i]->name() == nodeName) {
      bitmap = (NtfsNode *)children[i];
      if (bitmap->getMftEntry() != 6) { // $Bitmap metafile is always entry #6
	bitmap = NULL;
      }
    }
    ++i;
  }
  if (bitmap == NULL) {
    DEBUG(CRITICAL, "Can't find a valid $Bitmap metafile\n");
    return ;
  }

#if __WORDSIZE == 64
  DEBUG(CRITICAL, "Opening $Bitmap file, %lu bytes.\n", bitmap->size());
#else
  DEBUG(CRITICAL, "Opening $Bitmap file, %llu bytes.\n", bitmap->size());
#endif

  // Reads $Bitmap content
  data = new uint8_t[bitmap->size()];
  vfile = bitmap->open();
  vfile->read(data, bitmap->size());
  vfile->close();

  i = 0;
  while (i != bitmap->size()) {

    DEBUG(CRITICAL, "0x%x bytes is 0x%x\n", i, data[i]);
    for (bit = 0x1; ; bit <<= 1 ) {	// Iterates inside each bit
      DEBUG(CRITICAL, " %c %lu %lu\n", ((data[i] & bit) ? '1' : '0'), clusterIndex, unallocChunkStart);

      if (!((data[i] & bit) || inUnalloc)) {
	unallocChunkStart = clusterIndex;
	/* Must use a boolean in case of $Bitmap file starting with unallocated
	   area unallocChunkStart remains 0 */
	inUnalloc = true;
      }
      if ((data[i] & bit) && inUnalloc) {
	std::ostringstream	unallocChunkName;
	unallocChunkName << unallocChunkStart << "--" << clusterIndex;
	// Creates a 'by addresses' node
	new BitmapNode(unallocChunkName.str(), (clusterIndex - unallocChunkStart) * _boot->clusterSize(), _unallocRootNode, _node, this, unallocChunkStart, _boot->clusterSize());

	unallocChunkStart = 0;
	inUnalloc = false;
      }

      ++clusterIndex;
      if (bit == 0x80)
	/* 0x80 = b10000000 = MSB mask
	   Don't loop ; uint8_t overflow */
	break;
    }

    ++i;
  }

  if (inUnalloc) { // End of $Bitmap file reached ending with unallocated area
    std::ostringstream	unallocChunkName;
    unallocChunkName << unallocChunkStart << "--" << clusterIndex;
    new Node(unallocChunkName.str(), (clusterIndex - unallocChunkStart) * _boot->clusterSize(), unallocatedByAddresses, NULL);
  }

  delete data;
}

void	Ntfs::_setStateInfo(std::string currentState)
{
  stateinfo = currentState;
  _currentState = currentState;
}

void			Ntfs::_setStateInfo(uint32_t percent)
{
  std::ostringstream	stateBuff;

  stateBuff.str("");
  stateBuff << percent << "% " << _currentState;
  stateinfo = stateBuff.str();
}

void		Ntfs::start(std::map<std::string, Variant_p > args)
{
  uint64_t	offset = 0;
  uint16_t	mftEntryNumber;
  std::map<std::string, Variant_p >::iterator	it;
  bool          noorphan = false;
  bool          unalloc = true;

  if ((it = args.find("mftdecode")) != args.end())
    this->_mftDecode = it->second->value<uint64_t>();
  else
    this->_mftDecode = (uint64_t)-1;
#if __WORDSIZE == 64
      DEBUG(INFO, "Only have to decode mft entry at offset 0x%lx\n", _mftDecode);
#else
      DEBUG(INFO, "Only have to decode mft entry at offset 0x%llx\n", _mftDecode);
#endif
  if ((it = args.find("indexdecode")) != args.end())
    this->_indexDecode = it->second->value<uint64_t>();
  else
    this->_indexDecode = (uint64_t)-1;
#if __WORDSIZE == 64
      DEBUG(INFO, "Only have to decode index entries at offset 0x%lx\n", _indexDecode);
#else
      DEBUG(INFO, "Only have to decode index entries at offset 0x%llx\n", _indexDecode);
#endif
  if ((it = args.find("no-orphan")) != args.end())
     noorphan = true;

  if ((it = args.find("no-bitmap-parse")) != args.end()) {
    DEBUG(CRITICAL, "Will create unallocated space as $Bitmap children\n");
    unalloc = false;
  }

  /* Assume NTFS Boot sector is present */
  if ((it = args.find("file")) != args.end())
    {
      try
	{
	  this->_node = it->second->value<Node*>();
	  _vfile = _node->open();
	  
	  _boot = new Boot(_vfile);
	  _mftEntry = new MftEntry(_vfile); //XXX TMP VFILE
	  
#if __WORDSIZE == 64
      if (_boot->isBootBlock(offset) && _mftDecode == 0x0UL - 1 && _indexDecode == 0x0UL - 1)
#else
      if (_boot->isBootBlock(offset) && _mftDecode == 0x0ULL - 1 && _indexDecode == 0x0ULL - 1)
#endif
	{
	  /* Set offset to first MFT Entry */
	  offset = _boot->clusterSize() * _boot->getBootBlock()->startMft;
	  /* Set size of read buffer 
	   * and set size of a tree node */
	  _mftEntry->clusterSize(_boot->clusterSize());
	  _mftEntry->indexRecordSize(_boot->indexRecordSize());
	  _mftEntry->sectorSize(_boot->sectorSize());
	  _mftEntry->mftEntrySize(_boot->mftEntrySize());
	  
	  _setStateInfo("Boot block found");
	}
#if __WORDSIZE == 64
      else if (_mftDecode == 0x0UL - 1 && _indexDecode == 0x0UL - 1)
#else
      else if (_mftDecode == 0x0ULL - 1 && _indexDecode == 0x0ULL - 1)
#endif
	{
	  std::cerr << "No NTFS Boot Sector found" << std::endl;
	  _setStateInfo(std::string("No NTFS Boot Sector found"));
	}
#if __WORDSIZE == 64
      else if (_mftDecode != 0x0UL -1)
#else
      else if (_mftDecode != 0x0ULL - 1)
#endif
	{
	  std::ostringstream	result;

	// switching to mft decode only, usefull for DC3 2k10 
	_mftEntry->clusterSize(4096);
	_mftEntry->indexRecordSize(4096);
	_mftEntry->sectorSize(512);
	_mftEntry->mftEntrySize(1024);
	if (_mftEntry->decode(_mftDecode)) {
	  Attribute		*attribute;

	  //_mftEntry->dumpHeader();
#if __WORDSIZE == 64
	  printf("Decoding MFT entry at offset 0x%lx\n", _mftDecode);
#else
	  printf("Decoding MFT entry at offset 0x%llx\n", _mftDecode);
#endif
	  while ((attribute = _mftEntry->getNextAttribute())) {
	    attribute->readHeader();
	    attribute->dumpHeader();
	    if (attribute->getType() == ATTRIBUTE_DATA) {
	      AttributeData *_data = new AttributeData(*attribute);
	      
	      _data->setRunList();
	    }
	    _mftEntry->dumpAttribute(attribute);
	  }
	  result << "MFT entry at offset " << _mftDecode << " (0x" << std::hex << _mftDecode << ") decoded, see std::out";
	}
	else {
	  result << "Unable to decode MFT entry at offset " << _mftDecode << " (0x" << std::hex << _mftDecode << ")";
	}
	_setStateInfo(std::string(result.str()));
	return ;
      }
#if __WORDSIZE == 64
      else if (_indexDecode != 0x0UL - 1)
#else
      else if (_indexDecode != 0x0ULL - 1)
#endif
	{
	  // switching to index decode only
	  AttributeIndexAllocation	*content = new AttributeIndexAllocation(_vfile, _indexDecode);
	  std::ostringstream		result;
	  
#if __WORDSIZE == 64
	  printf("Decoding Index entry at offset 0x%lx\n", _indexDecode);
#else
	  printf("Decoding Index entry at offset 0x%llx\n", _indexDecode);
#endif
	  content->dumpNodeHeader();
	  content->dumpEntries();

	  result << "Index record entry at offset " << _indexDecode << " (0x" << std::hex << _indexDecode << ") decoded, see std::out";
	  _setStateInfo(std::string(result.str()));
	  return ;
	}
      
      /* MFTEntry size related
       */
      if (!_boot->mftEntrySize()) {
	// No mft entry size discovered, so discover it
	DEBUG(INFO, "No MFTEntry size found, trying to search it\n");

	_boot->mftEntrySize(_mftEntry->discoverMftEntrySize(offset));
      }

      /*  in case mftEntrySize is not present in boot block 
       */
      if (!_boot->mftEntrySize() &&
	  _boot->isPow2(_mftEntry->getMftEntryBlock()->allocatedSizeMftEntry)) {
	/* Set MFT entry size if ones in bootsector is invalid */

	_boot->mftEntrySize(_mftEntry->getMftEntryBlock()->allocatedSizeMftEntry);
      }
      if (_boot->mftEntrySize() == 0) {

	/* Unable to find mft entry size either in bootsector or directly in an mft entry */
	DEBUG(INFO, "Unable to find mft entry size either in bootsector or directly in an mft entry\n");
	throw(vfsError(std::string("Unable to find mft entry size either in bootsector or directly in an mft entry")));
      }

      _mftEntry->mftEntrySize(_boot->mftEntrySize());

      if (_mftEntry->isMftEntryBlock(offset)) {
	// Mft is valid

	DEBUG(INFO, "\tValid MFTEntry found\n");
	_root = new NtfsNode("NTFS", 0, NULL, this, _boot->getBootBlock());

	mftEntryNumber = 0;
	_mftMainFile = new MftFile(_vfile, _boot->mftEntrySize(),
				   _boot->indexRecordSize(),
				   _boot->sectorSize(),
				   _boot->clusterSize());
	_setMftMainFile(offset);
	
	// search every files in MFT
	
	_setStateInfo("Searching for regular files and directories");
	_walkMftMainFile();
        if (noorphan == false) {
	  _setStateInfo("Searching for deleted and orphans files and directories");
	  DEBUG(INFO, "Searching for deleted and orphans files\n");
	  _checkOrphanEntries();
	}
	if (unalloc == true) {
	  _setStateInfo("Read $Bitmap to create unallocated space nodes");
	  DEBUG(INFO, "Read $Bitmap to create unallocated space nodes\n");
	  _unallocRootNode = new NtfsNode("NTFS unallocated", 0, NULL, this, false, NULL, NULL, NULL);
	  _readBitmap();
	}

	_setStateInfo("Done");
      }
      else {
	std::cerr << "No NTFS MFT Entry found" << std::endl;
	_setStateInfo(std::string("No NTFS MFT Entry found"));
      }


      if (_node && _root) {
	registerTree(_node, _root);
      }
      if (_node && _unallocRootNode) {
	registerTree(_node, _unallocRootNode);
      }
    }
  catch (vfsError & e)
    {
      std::cerr << "Exception vfsError caught in module Ntfs method start(): " << e.error << std::endl;
      _setStateInfo(std::string(e.error));
      //throw e;
    }
  catch (envError & e)
    {
      std::cerr << "Exception envError caught in module Ntfs method start(): " << e.error << std::endl;
      _setStateInfo(e.error);
      //throw e;
    }
  catch (std::exception & e)
    {
      std::cerr << "Exception std::exception caught in module Ntfs method start(): " << e.what() << std::endl;
      _setStateInfo(e.what());
      //throw e;
    }
    }
  else
    {
      std::cerr << "Ntfs method start(): no file provided" << std::endl;
    }
}

