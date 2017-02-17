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

#include "fatnodes.hpp"

FileSlack::FileSlack(std::string name, uint64_t size, Node* parent, class Fatfs* fs) : Node(name, size, parent, fs)
{
  this->__fs = fs;
}

FileSlack::~FileSlack()
{
}

void		FileSlack::setContext(uint32_t ocluster, uint64_t originsize)
{
  this->__ocluster = ocluster;
  this->__originsize = originsize;
}

void		FileSlack::fileMapping(FileMapping* fm)
{
  std::vector<uint64_t>	clusters;
  uint64_t		idx;
  uint64_t		remaining;
  uint64_t		voffset;
  uint64_t		clustsize;

  voffset = 0;
  clustsize = (uint64_t)this->__fs->bs->csize * this->__fs->bs->ssize;
  clusters = this->__fs->fat->clusterChainOffsets(this->__ocluster);
  if (clusters.size() > 0)
    {
      idx = this->__originsize / clustsize;
      remaining = this->__originsize % clustsize;
      //first chunk can be truncated
      fm->push(voffset, clustsize - remaining, this->__fs->parent, clusters[idx] + remaining);
      voffset += (clustsize - remaining);
      idx++;
      while (idx != clusters.size())
	{
	  fm->push(voffset, clustsize, this->__fs->parent, clusters[idx]);
	  voffset += clustsize;
	  idx++;
	}
    }
}

Attributes	FileSlack::_attributes()
{
  Attributes	attrs;

  //attrs["starting offset"] = new Variant(this->__offset);
  return attrs;
}


UnallocatedSpace::UnallocatedSpace(std::string name, uint64_t size, Node* parent, class Fatfs* fs): Node(name, size, parent, fs)
{
  this->__fs = fs;
}

UnallocatedSpace::~UnallocatedSpace()
{
}

void		UnallocatedSpace::setContext(uint32_t scluster, uint32_t count)
{
  this->__scluster = scluster;
  this->__count = count;
}

void		UnallocatedSpace::fileMapping(FileMapping* fm)
{
  uint64_t	soffset;
  uint64_t	size;

  soffset = this->__fs->fat->clusterToOffset(this->__scluster);
  size = (uint64_t)this->__count * this->__fs->bs->csize * this->__fs->bs->ssize;
  fm->push(0, size, this->__fs->parent, soffset);
}

Attributes	UnallocatedSpace::_attributes(void)
{
  Attributes	attrs;

  attrs["starting cluster"] = Variant_p(new Variant(this->__scluster));
  attrs["total clusters"] = Variant_p(new Variant(this->__count));
  return attrs;
}


Attributes	UnallocatedSpace::dataType()
{
  Attributes	dtype;

  dtype["fatfs"] = Variant_p(new Variant(std::string("unallocated space")));
  return dtype;
}


ReservedSectors::ReservedSectors(std::string name, uint64_t size, Node* parent, class Fatfs* fs) : Node(name, size, parent, fs)
{
  this->fs = fs;
}

ReservedSectors::~ReservedSectors()
{
}

Attributes	ReservedSectors::dataType()
{
  Attributes	dtype;

  dtype["fatfs"] = Variant_p(new Variant(std::string("reserved sectors")));
  return dtype;
}

void		ReservedSectors::fileMapping(FileMapping* fm)
{
  fm->push(0, (uint64_t)(this->fs->bs->reserved) * (uint64_t)this->fs->bs->ssize, this->fs->parent, 0);
}

Attributes	ReservedSectors::_attributes(void)
{
  Attributes	attrs;

  attrs["starting sector"] = Variant_p(new Variant(1));
  attrs["total sectors"] = Variant_p(new Variant(this->fs->bs->reserved));
  return attrs;
}


FileSystemSlack::FileSystemSlack(std::string name, uint64_t size, Node* parent, class Fatfs* fs) : Node(name, size, parent, fs)
{
  this->fs = fs;
}

FileSystemSlack::~FileSystemSlack()
{
}

void		FileSystemSlack::fileMapping(FileMapping* fm)
{
  uint64_t	offset;
  uint64_t	size;

  offset = this->fs->bs->totalsize;
  size = this->fs->parent->size() - offset;
  fm->push(0, size, this->fs->parent, offset);
}

Attributes	FileSystemSlack::_attributes(void)
{
  Attributes	attrs;
  uint64_t	esect;
  uint64_t	tsect;
  uint64_t	ssect;
  
  esect = this->fs->parent->size() / this->fs->bs->ssize;
  tsect = (this->fs->parent->size() - this->fs->bs->totalsize) / this->fs->bs->ssize;
  ssect = esect - tsect;
  attrs["ending sector"] = Variant_p(new Variant(esect));
  attrs["total sectors"] = Variant_p(new Variant(tsect));
  attrs["starting sector"] = Variant_p(new Variant(ssect));
  return attrs;
}


Attributes	FileSystemSlack::dataType()
{
  Attributes	dtype;

  dtype["fatfs"] = Variant_p(new Variant(std::string("file system slack")));
  return dtype;
}


FatNode::FatNode(std::string name, uint64_t size, Node* parent, class Fatfs* fs): Node(name, size, parent, fs)
{
  this->fs = fs;
}

FatNode::~FatNode()
{
}

void		FatNode::setLfnMetaOffset(uint64_t lfnmetaoffset)
{
  this->lfnmetaoffset = lfnmetaoffset;
}

void		FatNode::setDosMetaOffset(uint64_t dosmetaoffset)
{
  this->dosmetaoffset = dosmetaoffset;
}

void		FatNode::setCluster(uint32_t cluster, bool reallocated)
{
  this->__clustrealloc = reallocated;
  this->cluster = cluster;
}

void		FatNode::fileMapping(FileMapping* fm)
{
  std::vector<uint64_t>	clusters;
  unsigned int		i;
  uint64_t		voffset;
  uint64_t		clustsize;
  uint64_t		rsize;


  voffset = 0;
  rsize = this->size();
  clustsize = (uint64_t)this->fs->bs->csize * this->fs->bs->ssize;
  if (!this->__clustrealloc || (this->__clustrealloc && !this->isDeleted()))
    {
      clusters = this->fs->fat->clusterChainOffsets(this->cluster);
      uint64_t	clistsize = clusters.size();
      //cluster chain is not complete
      if (clistsize > 0)
	{
	  if ((clistsize*clustsize) < this->size())
	    {
	      for (i = 0; i != clistsize; i++)
		{
		  fm->push(voffset, clustsize, this->fs->parent, clusters[i]);
		  voffset += clustsize;
		}
	      uint64_t	gap = this->size() - clistsize*clustsize;
	      //last chunk corresponds to the last gap between last cluster and the size and is
	      //based on the following blocks of the last cluster
	      fm->push(voffset, gap, this->fs->parent, clusters[clistsize-1]+clustsize);
	    }
	  else
	    {
	      //manage the mapping based on cluster chain untill node->size() is reached
	      for (i = 0; i != clusters.size(); i++)
		{
		  if (rsize < clustsize)
		    fm->push(voffset, rsize, this->fs->parent, clusters[i]);
		  else
		    fm->push(voffset, clustsize, this->fs->parent, clusters[i]);
		  rsize -= clustsize;
		  voffset += clustsize;
		}
	    }
	}
    }
}



Attributes		FatNode::_attributes()
{
  Attributes		attr;
  VFile*		vf;
  std::vector<uint32_t>	clusters;
  uint8_t*		entry;
  EntriesManager*	em;
  dosentry*		dos;

  em = new EntriesManager(this->fs->bs->fattype);
  vf = this->fs->parent->open();
  attr["lfn entries start offset"] =  Variant_p(new Variant(this->lfnmetaoffset));
  attr["dos entry offset"] = Variant_p(new Variant(this->dosmetaoffset));
  if ((entry = (uint8_t*)malloc(sizeof(dosentry))) != NULL)
    {
      vf->seek(this->dosmetaoffset);
      if (vf->read(entry, sizeof(dosentry)) != sizeof(dosentry))
	{
	  free(entry);
	  return attr;
	}
      dos = em->toDos(entry);
      free(entry);
      attr["modified"] = Variant_p(new Variant(new vtime(dos->mtime, dos->mdate)));
      attr["accessed"] = Variant_p(new Variant(new vtime(0, dos->adate)));
      attr["created"] = Variant_p(new Variant(new vtime(dos->ctime, dos->cdate)));
      attr["dos name (8+3)"] = Variant_p(new Variant(em->formatDosname(dos)));
      delete em;
      attr["Read Only"] = Variant_p(new Variant(bool(dos->attributes & ATTR_READ_ONLY)));
      attr["Hidden"] = Variant_p(new Variant(bool(dos->attributes & ATTR_HIDDEN)));
      attr["System"] = Variant_p(new Variant(bool(dos->attributes & ATTR_SYSTEM)));
      attr["Archive"] = Variant_p(new Variant(bool(dos->attributes & ATTR_ARCHIVE)));
      attr["Volume"] = Variant_p(new Variant(bool(dos->attributes & ATTR_VOLUME)));
      delete dos;
      try
      	{
      	  uint64_t clustsize = (uint64_t)this->fs->bs->csize * this->fs->bs->ssize;
      	  if (this->__clustrealloc)
      	    attr["first cluster (!! reallocated to another existing entry)"] = Variant_p(new Variant(this->cluster));
      	  else
      	    {
      	      if (!this->isDeleted() && this->size())
      		{
      		  clusters = this->fs->fat->clusterChain(this->cluster);
		  uint64_t clistsize = clusters.size();
		  attr["allocated clusters"] = Variant_p(new Variant(clistsize));
		  if (this->size() < clistsize * clustsize)
		    {
		      uint64_t	ssize = clistsize * clustsize - this->size();
		      attr["slack space size"] = Variant_p(new Variant(ssize));
		    }
		  else
		    {
		      uint32_t	missclust;
		      uint64_t	gap;
		      gap = this->size() - clistsize * clustsize;
		      missclust = gap / clustsize;
		      attr["file truncated"] = Variant_p(new Variant(true));
		      attr["missing cluters"] = Variant_p(new Variant(missclust));
		      attr["missing size"] = Variant_p(new Variant(gap));
		    }
		}
      	      //for (i = 0; i != clusters.size(); i++)
      	      //clustlist.push_back(new Variant(clusters[i]));
      	      attr["first cluster"] = Variant_p(new Variant(this->cluster));
      	      //attr["allocated clusters"] = new Variant(clustlist);
      	    }
      	}
      catch(vfsError e)
      	{
      	}
    }
  if (vf != NULL)
    {
      vf->close();
      delete vf;
    }
  return attr;
}
