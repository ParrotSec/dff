/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include "fat.hpp"

FileAllocationTableNode::FileAllocationTableNode(std::string name, uint64_t size, Node* parent, class Fatfs* fatfs) : Node(name, size, parent, fatfs)
{
}

FileAllocationTableNode::~FileAllocationTableNode()
{
}

void			FileAllocationTableNode::setContext(FileAllocationTable* fat, uint8_t fatnum)
{
  this->__fat = fat;
  this->__fatnum = fatnum;
}

void			FileAllocationTableNode::fileMapping(FileMapping* fm)
{
  this->__fat->fileMapping(fm, this->__fatnum);
}

Attributes		FileAllocationTableNode::_attributes(void)
{
  return this->__fat->attributes(this->__fatnum);
}

Attributes		FileAllocationTableNode::dataType(void)
{
  Attributes	dtype;

  dtype["fatfs"] = Variant_p(new Variant(std::string("File allocation table")));
  return dtype;
}


FileAllocationTable::FileAllocationTable()
{
  this->vfile = NULL;
}

// FileAllocationTable::FileAllocationTable(fsinfo* ctx, mfso* fsobj, Node* parent): Decoder("Fat module File Allocation Table reader")
// {
//   this->ctx = ctx;
//   this->fsobj = fsobj;
// }

FileAllocationTable::~FileAllocationTable()
{
  if (this->vfile != NULL)
    {
      //XXX VFile dtor must close the opened file...
      this->vfile->close();
      delete this->vfile;
    }
}

void	FileAllocationTable::setContext(Node* origin, Fatfs* fatfs)
{
  std::stringstream	sstr;
  uint64_t		offset;
  uint32_t		freeclust;
  uint32_t		badclust;
  uint32_t		alloclust;
  uint32_t		cidx, clustent;

  this->origin = origin;
  this->fatfs = fatfs;
  this->bs = fatfs->bs;
  offset = 0;
  try
    {
      this->vfile = this->origin->open();
      if ((this->bs->fatsize < 1024*1024*10) && ((this->__fat = malloc(this->bs->fatsize)) != NULL))
	{
	  offset = this->bs->firstfatoffset;
	  this->vfile->seek(offset);
	  if (this->vfile->read(this->__fat, this->bs->fatsize) != (int32_t)this->bs->fatsize)
	    throw (std::string("cannot read fat"));
	}
      else
	this->__fat = NULL;
      for (uint8_t i = 0; i != this->bs->numfat; i++)
	{
	  sstr << "gathering information for FAT " << i+1 << " / " << this->bs->numfat;
	  this->fatfs->stateinfo = sstr.str();
	  freeclust = 0;
	  badclust = 0;
	  alloclust = 0;
	  for (cidx = 0; cidx != this->bs->totalcluster; cidx++)
	    {
	      clustent = this->clusterEntry(cidx, i);
	      if (this->isFreeCluster(clustent))
		freeclust++;
	      else if (this->isBadCluster(clustent))
		badclust++;
	      else
		alloclust++;
	    }
	  this->__freeClustCount[i] = freeclust;
	  this->__badClustCount[i] = badclust;
	  this->__allocClustCount[i] = alloclust;
	  sstr.str("");
	}
    }
  catch(vfsError e)
    {
      this->vfile = NULL;
      throw("Fat module: FileAllocationTable error while opening node" + e.error);
    }
}

uint64_t	FileAllocationTable::clusterOffsetInFat(uint64_t cluster, uint8_t which)
{
  uint64_t	baseoffset;
  uint64_t	idx;
  uint64_t	fatsectnum;
  uint64_t	fatentryoffset;

  baseoffset = this->bs->firstfatoffset + (uint64_t)which * (uint64_t)this->bs->fatsize;
  if (this->bs->fattype == 12)
    idx = cluster + cluster / 2;
  if (this->bs->fattype == 16)
    idx = cluster * 2;
  if (this->bs->fattype == 32)
    idx = cluster * 4;
  fatsectnum = idx / this->bs->ssize;
  fatentryoffset = idx % this->bs->ssize;
  idx = fatsectnum * this->bs->ssize + fatentryoffset;
  return (baseoffset + idx);
}

uint32_t	FileAllocationTable::ioCluster12(uint32_t current, uint8_t which)
{
  uint16_t	next;
  uint64_t	offset;

  offset = this->clusterOffsetInFat((uint64_t)current, which);
  this->vfile->seek(offset);
  if (this->vfile->read(&next, 2) == 2)
    return (uint32_t)next;
  else
    return 0;
}

uint32_t	FileAllocationTable::ioCluster16(uint32_t current, uint8_t which)
{
  uint16_t	next;
  uint64_t	offset;

  offset = this->clusterOffsetInFat((uint64_t)current, which);
  this->vfile->seek(offset);
  if (this->vfile->read(&next, 2) == 2)
    return (uint32_t)next;
  else
    return 0;
}

uint32_t	FileAllocationTable::ioCluster32(uint32_t current, uint8_t which)
{
  uint32_t	next;
  uint64_t	offset;

  offset = this->clusterOffsetInFat((uint64_t)current, which);
  this->vfile->seek(offset);
  if (this->vfile->read(&next, 4) == 4)
    return next;
  else
    return 0;
}

uint32_t	FileAllocationTable::cluster12(uint32_t current, uint8_t which)
{
  uint16_t	next;
  uint32_t	idx;

  next = 0;
  if (which < this->bs->numfat)
    {
      if (which == 0 && this->__fat != NULL)
	{
	  idx = current + current / 2;
	  idx = ((idx / this->bs->ssize) * this->bs->ssize) + (idx % this->bs->ssize);
	  memcpy(&next, (uint8_t*)this->__fat+idx, 2);
	}
      else
	next = this->ioCluster12(current, which);
      if (current & 0x0001)
	next = next >> 4;
      else
	next &= 0x0FFF;
    }
  return (uint32_t)next;
}

uint32_t	FileAllocationTable::cluster16(uint32_t current, uint8_t which)
{
  uint16_t	next;

  next = 0;
  if (which < this->bs->numfat)
    {
      if (which == 0 && this->__fat != NULL)
	next = *((uint16_t*)this->__fat+current);
      else
	next = this->ioCluster16(current, which);
    }
  return (uint32_t)next;
}

uint32_t	FileAllocationTable::cluster32(uint32_t current, uint8_t which)
{
  uint32_t	next;

  next = 0;
  if (which < this->bs->numfat)
    {
      if (which == 0 && this->__fat != NULL)
	next = *((uint32_t*)this->__fat+current);
      else
	next = this->ioCluster32(current, which);
      next &= 0x0FFFFFFF;
    }
  return next;
}

uint32_t	FileAllocationTable::clusterEntry(uint32_t current, uint8_t which)
{
  uint32_t	next;

  next = 0;
  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else if (current > this->bs->totalcluster)
    throw(vfsError(std::string("Fat module: provided cluster is too high")));
  else
    {
      if (this->bs->fattype == 12)
	next = this->cluster12(current, which);
      if (this->bs->fattype == 16)
	next = this->cluster16(current, which);
      if (this->bs->fattype == 32)
	next = this->cluster32(current, which);
    }
  return next;
}

std::vector<uint64_t>	FileAllocationTable::clusterChainOffsets(uint32_t cluster, uint8_t which)
{
  std::vector<uint64_t>	clustersoffset;
  std::vector<uint32_t>	clusters;
  uint64_t		offset;
  uint32_t		i;

  clusters = this->clusterChain(cluster, which);
  for (i = 0; i != clusters.size(); i++)
    {
      offset = this->clusterToOffset(clusters[i]);
      clustersoffset.push_back(offset);
    }
  return clustersoffset;
}

std::vector<uint32_t>	FileAllocationTable::clusterChain(uint32_t cluster, uint8_t which)
{
  std::vector<uint32_t>	clusters;
  std::set<uint32_t>	parsed;
  uint64_t		max;
  uint32_t		eoc;

  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else if (cluster > this->bs->totalcluster)
    throw(vfsError(std::string("Fat module: provided cluster is too high")));
  else
    {
      if (this->bs->fattype == 12)
	eoc = 0x0FF8;
      if (this->bs->fattype == 16)
	eoc = 0xFFF8;
      if (this->bs->fattype == 32)
	eoc = 0x0FFFFFF8;
      max = 0;
      while ((cluster > 1) && (cluster < eoc) && (max < 0xFFFFFFFFL) && !this->isBadCluster(cluster) && (parsed.find(cluster) == parsed.end()))
	{
	  clusters.push_back(cluster);
	  parsed.insert(cluster);
	  max += this->bs->csize;
	  try
	    {
	      cluster = this->clusterEntry(cluster);
	    }
	  catch(vfsError e)
	    {
	      break;
	    }
	}
    }
  return clusters;
}

/*
/=========================================================\
| For each list*Clusters(uint8_t which), compute a bitmap |
\=========================================================/
*/

bool			FileAllocationTable::isFreeCluster(uint32_t cluster)
{
  return cluster == 0 ? true : false;
}

bool			FileAllocationTable::isBadCluster(uint32_t cluster)
{
  if (this->bs->fattype == 12)
    return cluster == 0x0FF7 ? true : false;
  if (this->bs->fattype == 16)
    return cluster == 0xFFF7 ? true : false;
  if (this->bs->fattype == 32)
    return cluster == 0x0FFFFFF7 ? true : false;
  return false;
}


bool			FileAllocationTable::clusterEntryIsFree(uint32_t cluster, uint8_t which)
{
  if (this->bs->fattype == 12)
    return (this->cluster12(cluster, which) == 0 ? true : false);
  if (this->bs->fattype == 16)
    return (this->cluster16(cluster, which) == 0 ? true : false);
  if (this->bs->fattype == 32)
    return (this->cluster32(cluster, which) == 0 ? true : false);
  return false;
}


bool			FileAllocationTable::clusterEntryIsBad(uint32_t cluster, uint8_t which)
{
  if (this->bs->fattype == 12)
    return (this->cluster12(cluster, which) == 0x0FF7 ? true : false);
  if (this->bs->fattype == 16)
    return (this->cluster16(cluster, which) == 0xFFF7 ? true : false);
  if (this->bs->fattype == 32)
    return (this->cluster32(cluster, which) == 0x0FFFFFF7 ? true : false);
  return false;
}


std::vector<uint64_t>	FileAllocationTable::listFreeClustersOffset(uint8_t which)
{
  uint32_t		cidx;
  std::vector<uint64_t>	freeclusters;

  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    for (cidx = 0; cidx != this->bs->totalcluster; cidx++)
      if (this->clusterEntryIsFree(cidx, which))
	freeclusters.push_back(this->clusterToOffset(cidx));
  return freeclusters;
}

std::vector<uint32_t>	FileAllocationTable::listFreeClusters(uint8_t which)
{
  uint32_t		cidx;
  std::vector<uint32_t>	freeclusters;

  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    for (cidx = 0; cidx != this->bs->totalcluster; cidx++)
      if (this->clusterEntryIsFree(cidx, which))
	freeclusters.push_back(cidx);
  return freeclusters;
}

uint32_t		FileAllocationTable::freeClustersCount(uint8_t which)
{
  uint32_t					freeclust;
  uint32_t					cidx;
  std::map<uint32_t, uint32_t>::iterator	it;

  freeclust = 0;
  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    {
      if ((it = this->__freeClustCount.find(which)) != this->__freeClustCount.end())
	freeclust = it->second;
      else
	{
	  for (cidx = 0; cidx != this->bs->totalcluster; cidx++)
	    if (this->clusterEntryIsFree(cidx, which))
	      freeclust++;
	  this->__freeClustCount[which] = freeclust;
	}
    }
    return freeclust;
}

std::list<uint32_t>	FileAllocationTable::listAllocatedClusters(uint8_t which)
{
  std::list<uint32_t>	alloc;

  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    return alloc;
}

uint32_t		FileAllocationTable::allocatedClustersCount(uint8_t which)
{
  uint32_t					cidx;
  uint32_t					alloc;
  std::map<uint32_t, uint32_t>::iterator	it;
  uint32_t					clustent;

  alloc = 0;
  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    {
      if ((it = this->__allocClustCount.find(which)) != this->__allocClustCount.end())
	alloc = it->second;
      else
	{
	  for (cidx = 0; cidx != this->bs->totalcluster; cidx++)
	    {
	      clustent = this->clusterEntry(cidx, which);
	      if (!this->isFreeCluster(clustent) && !this->isBadCluster(clustent))
	      alloc++;
	    }
	  this->__allocClustCount[which] = alloc;
	}
    }
  return alloc;
}


std::vector<uint32_t>	FileAllocationTable::listBadClusters(uint8_t which)
{
  std::vector<uint32_t>	badclust;
  uint32_t		cidx;

  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    for (cidx = 0; cidx != this->bs->totalcluster; cidx++)
      if (this->clusterEntryIsBad(cidx, which))
	badclust.push_back(cidx);
  return badclust;
}

uint32_t					FileAllocationTable::badClustersCount(uint8_t which)
{
  uint32_t					badclust = 0;
  uint32_t					cidx;
  std::map<uint32_t, uint32_t>::iterator	it;


  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    {
      if ((it = this->__badClustCount.find(which)) != this->__badClustCount.end())
	badclust = it->second;
      else
	{
	  for (cidx = 0; cidx != this->bs->totalcluster; cidx++)
	    if (this->clusterEntryIsBad(cidx, which))
	      badclust++;
	  this->__badClustCount[which] = badclust;
	}
    }
  return badclust;
}

uint64_t		FileAllocationTable::clusterToOffset(uint32_t cluster)
{
  uint64_t	offset;

  if (this->bs->fattype == 12)
    cluster &= FATFS_12_MASK;
  if (this->bs->fattype == 16)
    cluster &= FATFS_16_MASK;
  if (this->bs->fattype == 32)
    cluster &= FATFS_32_MASK;
  offset = ((uint64_t)cluster - 2) * this->bs->csize * this->bs->ssize + this->bs->dataoffset;
  return offset;
}

uint32_t		FileAllocationTable::offsetToCluster(uint64_t offset)
{
  //FIXME
  return 0;
}

void			FileAllocationTable::diffFats()
{
}

void			FileAllocationTable::makeNodes(Node* parent)
{
  FileAllocationTableNode*	node;
  std::stringstream		sstr;
  uint8_t			i;

  for (i = 0; i != this->bs->numfat; i++)
    {
      sstr << "FAT " << i + 1;
      node = new FileAllocationTableNode(sstr.str(), this->bs->fatsize, parent, this->fatfs);
      //this->__fclusterscount.push_back(this->freeClustersCount(i));
      //this->__aclusterscount.push_back(this->allocatedClustersCount(i));
      node->setContext(this, i);
      sstr.str("");
    }
}

void			FileAllocationTable::fileMapping(FileMapping* fm, uint8_t which)
{
  uint64_t		offset;
  
  offset = this->bs->firstfatoffset + (uint64_t)which * (uint64_t)this->bs->fatsize;
  fm->push(0, this->bs->fatsize, this->origin, offset);
}

Attributes			FileAllocationTable::attributes(uint8_t which)
{
  Attributes		attrs;
  uint64_t		clustsize;
  uint32_t		badclust;
  
  
  clustsize = (uint64_t)this->bs->csize * this->bs->ssize;
  if (which < this->bs->numfat)
    {
      attrs["free clusters"] = Variant_p(new Variant(this->freeClustersCount(which)));
      attrs["free space"] = Variant_p(new Variant(clustsize * this->freeClustersCount(which)));
      attrs["allocated clusters"] = Variant_p(new Variant(this->allocatedClustersCount(which)));
      attrs["used space"] = Variant_p(new Variant(clustsize * this->allocatedClustersCount(which)));
      if ((badclust = this->badClustersCount(which)) != 0)
	{
	  attrs["bad clusters"] = Variant_p(new Variant(this->badClustersCount(which)));
	  attrs["bad clusters space"] = Variant_p(new Variant(clustsize * badclust));
	}
      else
	attrs["bad clusters"] = Variant_p(new Variant(0));
    }
  return attrs;
}
