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

#include "fattree.hpp"
#include <unicode/unistr.h>

FatTree::FatTree()
{
  //this->ectx = new EntryContext();
  //this->converter = new EntryConverter();
  this->__volname = "";
  this->depth = 0;
  this->allocatedClusters = new TwoThreeTree();
}

FatTree::~FatTree()
{
  this->vfile->close();
}


void	FatTree::rootdir(Node* parent)
{
  uint32_t			bpos;
  uint8_t*			buff;
  Node*				node;
  ctx*				c;

  buff = NULL;
  try
    {
      if ((buff = (uint8_t*)malloc(this->fs->bs->rootdirsize)) == NULL)
	return;
      this->vfile->seek(this->fs->bs->rootdiroffset);
      if (this->vfile->read(buff, this->fs->bs->rootdirsize) != (int32_t)this->fs->bs->rootdirsize)
	{
	  free(buff);
	  return;
	}
      for (bpos = 0; bpos != this->fs->bs->rootdirsize; bpos += 32)
	{
	  if (this->emanager->push(buff+bpos, this->fs->bs->rootdiroffset + bpos))
	    {
	      c = this->emanager->fetchCtx();
	      if ((c->valid) && (c->cluster < this->fs->bs->totalcluster))
		{
		  if (!c->deleted)
		    {
		      if (c->volume)
			this->__volname = c->dosname;
		      else
			{
			  node = this->allocNode(c, parent);
			  if (c->dir)
			    {
			      this->depth++;
			      this->walk(c->cluster, node);
			      this->depth--;
			    }
			  // else
			  //   this->updateAllocatedClusters(c->cluster);
			  delete c;
			}
		    }
		  else
		    this->updateDeletedItems(c, parent);
		}
	      else
		delete c;
	    }
	}
      free(buff);
    }
  catch(...)
    {
      if (buff != NULL)
	free(buff);
    }
}

void	hexlify(uint8_t *entry)
{
  char		hex[512];
  int		i;
  int		pos;

  memset(hex, 0, 512);
  pos = 0;
  for (i = 0; i != 32; i++)
    {
      if ((i % 4) == 0)
	{
	  sprintf(hex+pos, " ");
	  pos++;
	}
      if ((i == 20) || (i == 21))
	{
	  sprintf(hex+pos, "\e[32m");
	  pos += 5;
	}
      if ((i == 26) || (i == 27))
	{
	  sprintf(hex+pos, "\e[33m");
	  pos += 5;
	}
      if (entry[i] <= 15)
	{
	  sprintf(hex+pos, "0%x ", entry[i]);
	  pos += 3;
	}
      else
	{
	  sprintf(hex+pos, "%x ", entry[i]);
	  pos += 3;
	}
      if ((i == 20) || (i == 21) || (i == 26) || (i == 27))
	{
	  sprintf(hex+pos, "\e[m");
	  pos += 3;
	}
      if (i == 15)
	{
	  sprintf(hex+pos, "\n");
	  pos++;
	}
    }
  printf("%s\n", hex);
}


// void	FatTree::CheckSlackNode()
// {
//   void*					zeroed;
//   void*					buff;

//   if ((zeroed = malloc(clustsize)) != NULL)
//     memset(zeroed, 0, clustsize);
//   else
//     return;
//   if ((buff = malloc(clustsize)) == NULL)
//     {
//       free(zeroed);
//       return;
//     }
//   this->vfile->seek(offset);
//   if ((uint64_t)this->vfile->read(buff, size) == size)
//     if (memcmp(zeroed, buff, size) != 0)
//       {
// 	FileSlack* fslack = new FileSlack(mit->second->name() + ".SLACK", size, mit->second->parent(), this->fs);
// 	fslack->setContext(mit->first, mit->second->size());
//       }
//   free(buff);
//   free(zeroed);
// }


void	FatTree::makeSlackNodes()
{
  std::map<uint32_t, Node*>::iterator	mit;
  uint64_t				clustsize, slackcount;

  slackcount = this->_slacknodes.size();
  clustsize = (uint64_t)this->fs->bs->csize * this->fs->bs->ssize;
  if (slackcount != 0)
    {
      uint64_t			sprocessed, percent, prevpercent, size, clistsize;
      std::stringstream		sstr;
      std::vector<uint32_t>	clusters;
      sprocessed = percent = prevpercent = 0;
      for (mit = this->_slacknodes.begin(); mit != this->_slacknodes.end(); mit++)
	{
	  clusters = this->fs->fat->clusterChain(mit->first);
	  clistsize = clusters.size();
	  if (mit->second->size() < clistsize * clustsize)
	    {
	      size = clistsize * clustsize - mit->second->size();
	      FileSlack* fslack = new FileSlack(mit->second->name() + ".SLACK", size, mit->second->parent(), this->fs);
	      fslack->setContext(mit->first, mit->second->size());
	    }
	  percent = (sprocessed * 100) / slackcount;
	  if (prevpercent < percent)
	    {
	      sstr << "processing slack space for each regular files " << percent << "%";
	      this->fs->stateinfo = sstr.str();
	      sstr.str("");
	      prevpercent = percent;
	    }
	  sprocessed += 1;
	}
    }
}

Node*	FatTree::allocNode(ctx* c, Node* parent)
{
  FatNode*	node;
  
  if (!c->lfnname.empty())
    {
      UnicodeString	us(c->lfnname.data(), c->lfnname.size(), "UTF-16LE");
      std::string	utf8 = "";
      std::string ret = us.toUTF8String(utf8);
      node = new FatNode(std::string(utf8.data(), utf8.size()), c->size, parent, this->fs);
    }
  else
    node = new FatNode(c->dosname, c->size, parent, this->fs);
  if (!this->allocatedClusters->find(c->cluster))
    node->setCluster(c->cluster);
  else
    node->setCluster(c->cluster, true);
  if (c->deleted)
    node->setDeleted();
  if (c->dir)
    node->setDir();
  else
    {
      node->setFile();
      if (!c->deleted)
	{
	  this->updateAllocatedClusters(c->cluster);
	  this->_slacknodes[c->cluster] = node;
	}
    }
  node->setLfnMetaOffset(c->lfnmetaoffset);
  node->setDosMetaOffset(c->dosmetaoffset);
  return node;
}

void	FatTree::updateAllocatedClusters(uint32_t cluster)
{
  std::vector<uint32_t>		clusters;
  uint32_t			cidx;
  std::stringstream		sstr;

  if (cluster != 0)
    {
      this->allocatedClusters->insert(cluster);
      clusters = this->fs->fat->clusterChain(cluster);
      this->processed += clusters.size();
      sstr << "processing regular tree " << (this->processed * 100) / this->allocount << "%";
      this->fs->stateinfo = sstr.str();
      for (cidx = 0; cidx != clusters.size(); cidx++)
	if (clusters[cidx] != 0)
	  this->allocatedClusters->insert(clusters[cidx]);
    }
}

void	FatTree::updateDeletedItems(ctx* c, Node* parent)
{
  deletedItems*	d;

  d = new deletedItems;
  d->c = c;
  d->node = parent;
  this->deleted.push_back(d);
}

void	FatTree::walk(uint32_t cluster, Node* parent)
{
  std::vector<uint64_t>		clusters;
  uint32_t			cidx;
  uint32_t			bpos;
  uint8_t*			buff;
  Node*				node;
  ctx*				c;

  buff = NULL;
  try
    {
      this->updateAllocatedClusters(cluster);
      clusters = this->fs->fat->clusterChainOffsets(cluster);
      if ((buff = (uint8_t*)malloc(this->fs->bs->csize * this->fs->bs->ssize)) == NULL)
	return;
      for (cidx = 0; cidx != clusters.size(); cidx++)
	{
	  this->vfile->seek(clusters[cidx]);
	  if (this->vfile->read(buff, this->fs->bs->csize * this->fs->bs->ssize) != (this->fs->bs->csize * this->fs->bs->ssize))
	    {
	      free(buff);
	      return;
	    }
	  for (bpos = 0; bpos != this->fs->bs->csize * this->fs->bs->ssize; bpos += 32)
	    {
	      if (this->emanager->push(buff+bpos, clusters[cidx]+bpos))
		{
		  c = this->emanager->fetchCtx();
		  if ((c->valid) && (c->cluster < this->fs->bs->totalcluster))
		    {
		      if (c->volume)
			this->__volname = c->dosname;
		      else
			{
			  if (!c->deleted)
			    {
			      node = this->allocNode(c, parent);
			      if (c->dir)
				{
				  this->depth++;
				  this->walk(c->cluster, node);
				  this->depth--;
				}
			      delete c;
			    }
			  else
			    this->updateDeletedItems(c, parent);
			}
		    }
		  else
		    delete c;
		}
	    }
	}
      free(buff);
    }
  catch(...)
    {
      if (buff != NULL)
	free(buff);
    }
}

void	FatTree::walk_free(Node* parent)
{
  std::vector<uint32_t>		clusters;
  uint32_t			cidx;
  uint32_t			bpos;
  uint8_t*			buff;
  Node*				rootunalloc;
  ctx*				c;
  uint32_t			fcsize;
  std::stringstream		sstr;

  buff = NULL;
  try
    {
      rootunalloc = NULL;
      clusters = this->fs->fat->listFreeClusters();
      if ((buff = (uint8_t*)malloc(this->fs->bs->csize * this->fs->bs->ssize)) == NULL)
	return;
      fcsize = clusters.size();
      for (cidx = 0; cidx != fcsize; cidx++)
	{
	  sstr << "carving entries in free clusters " << ((cidx * 100) / fcsize) << "%";
	  this->fs->stateinfo = sstr.str();
	  sstr.str("");
	  if ((!this->allocatedClusters->find(clusters[cidx])) && (clusters[cidx] != 0))
	    {
	      uint64_t	clustoff;
	      clustoff = this->fs->fat->clusterToOffset(clusters[cidx]);
	      this->vfile->seek(clustoff);
	      if (this->vfile->read(buff, this->fs->bs->csize * this->fs->bs->ssize) != (this->fs->bs->csize * this->fs->bs->ssize))
		{
		  free(buff);
		  return;
		}
	      for (bpos = 0; bpos != this->fs->bs->csize * this->fs->bs->ssize; bpos += 32)
		{
		  if (*(buff+bpos) == 0xE5)
		    {
		      if (this->emanager->push(buff+bpos, clustoff+bpos))
			{
			  c = this->emanager->fetchCtx();
			  if (c->valid)
			    {
			      if (rootunalloc == NULL)
				{
				  rootunalloc = new Node("$OrphanedFiles", 0, NULL, this->fs);
				  rootunalloc->setDir();
				}
			      if ((c->size < this->fs->bs->totalsize) && (c->cluster < this->fs->bs->totalcluster))
				this->allocNode(c, rootunalloc);
			    }
			  delete c;
			}
		    }
		}
	    }
	}
      this->fs->stateinfo = std::string("carving entries in free clusters 100%");
      free(buff);
      if (rootunalloc != NULL)
      	this->fs->registerTree(parent, rootunalloc);
    }
  catch(...)
    {
      if (buff != NULL)
	free(buff);
    }  
}

void	FatTree::walkDeleted(uint32_t cluster, Node* parent)
{
  std::vector<uint32_t>		clusters;
  uint64_t			coffset;
  uint32_t			cidx;
  uint32_t			bpos;
  uint8_t*			buff;
  Node*				node;
  ctx*				c;

  buff = NULL;
  if ((!this->allocatedClusters->find(cluster)) && (cluster != 0))
    {
      try
	{
	  clusters = this->fs->fat->clusterChain(cluster);
	  if ((buff = (uint8_t*)malloc(this->fs->bs->csize * this->fs->bs->ssize)) == NULL)
	    return;
	  for (cidx = 0; cidx != clusters.size(); cidx++)
	    {
	      if ((!this->allocatedClusters->find(clusters[cidx])) && (clusters[cidx] != 0))
		{
		  coffset = this->fs->fat->clusterToOffset(clusters[cidx]);
		  this->vfile->seek(coffset);
		  if (this->vfile->read(buff, this->fs->bs->csize * this->fs->bs->ssize) != this->fs->bs->csize * this->fs->bs->ssize)
		    {
		      free(buff);
		      return;
		    }
		  for (bpos = 0; bpos != this->fs->bs->csize * this->fs->bs->ssize; bpos += 32)
		    {
		      if (this->emanager->push(buff+bpos, coffset+bpos))
			{
			  c = this->emanager->fetchCtx();
			  if ((c->valid) && (c->cluster < this->fs->bs->totalcluster))
			    {
			      if (c->deleted)
				{
				  node = this->allocNode(c, parent);
				  this->updateAllocatedClusters(cluster);
				  if ((c->dir) && (!this->allocatedClusters->find(c->cluster)))
				    this->walkDeleted(c->cluster, node);
				  this->updateAllocatedClusters(c->cluster);
				}
			    }
			  delete c;
			}
		    }
		}
	    }
	  free(buff);
	}
      catch(...)
	{
	  if (buff != NULL)
	    free(buff);
	}
    }
}

void	FatTree::processUnallocated(Node* parent, std::vector<uint32_t> &clusters)
{
  uint32_t			cidx;
  uint32_t			start;
  uint32_t			count;
  UnallocatedSpace*		unode;
  std::stringstream		sstr;

  start = count = (uint32_t)-1;
  for (cidx = 0; cidx != clusters.size(); cidx++)
    {
      if (clusters[cidx] != 0)
	{
	  if (start == (uint32_t)-1)
	    {
	      start = clusters[cidx];
	      count = 1;
	    }	
	  else
	    {
	      //current unallocated cluster starts another area. Push the current context and start another one
	      if (clusters[cidx] != start+count)
		{
		  sstr << start << "--" << start+count;
		  unode = new UnallocatedSpace(sstr.str(), (uint64_t)count*this->fs->bs->ssize*this->fs->bs->csize, parent, this->fs);
		  sstr.str("");
		  unode->setContext(start, count);
		  start = clusters[cidx];
		  count = 1;
		}
	      else
		count++;
	    }
	}
    }
  if (start != (uint32_t)-1)
    {
      sstr << start << "--" << start+count;
      unode = new UnallocatedSpace(sstr.str(), (uint64_t)count*this->fs->bs->ssize*this->fs->bs->csize, parent, this->fs);
      sstr.str("");
      unode->setContext(start, count);
    }
}


void	FatTree::processDeleted()
{
  uint32_t	i;
  Node*		node;
  deletedItems*	d;
  std::stringstream	sstr;
  uint32_t		dsize;

  dsize = this->deleted.size();
  for (i = 0; i != dsize; i++)
    {
      d = this->deleted[i];
      sstr << "processing deleted entries " << ((i * 100) / dsize) << "%";
      this->fs->stateinfo = sstr.str();
      sstr.str("");
      node = this->allocNode(d->c, d->node);
      if (d->c->dir)
	this->walkDeleted(d->c->cluster, node);
      delete d->c;
      delete d;
    }
  this->fs->stateinfo = std::string("processing deleted entries 100%");
}

void	FatTree::process(Node* origin, Fatfs* fs, Node* parent)
{
  this->origin = origin;
  this->fs = fs;
  try
    {
      this->vfile = this->origin->open();
      this->allocount = this->fs->fat->allocatedClustersCount(0);
      this->processed = 0;
      this->fs->stateinfo = std::string("processing regular tree 0%");
      this->emanager = new EntriesManager(this->fs->bs->fattype);
      if (this->fs->bs->fattype == 32)
	this->walk(this->fs->bs->rootclust, parent);
      else
	this->rootdir(parent);
      this->fs->stateinfo = std::string("processing regular tree 100%");
      this->makeSlackNodes();
      this->processDeleted();
      // int32_t	max = ucnv_countAvailable();
      // for (int32_t i = 0; i != max; i++)
      // 	printf("%04i -- %s\n", i, ucnv_getAvailableName(i));
      // printf("current --> %s\n", ucnv_getDefaultName());
    }
  catch(...)
    {
      throw("err");
    }
}
