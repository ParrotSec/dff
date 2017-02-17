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

#include "fatfs.hpp"

void		Fatfs::process()
{
  Node*			fsroot;
  std::string		volname;

  try
    {
      if (this->parent->size() > 0)
	{
	  this->vfile = this->parent->open();
	  this->bs->process(this->parent, this);
	  this->fat->setContext(this->parent, this);
	  fsroot = new Node("[root]", 0, NULL, this);
	  fsroot->setDir();
	  this->tree->process(this->parent, this, fsroot);
	  volname = this->tree->volname();
	  if (volname.empty())
	    this->root = new Node("NONAME", 0, NULL, this);  
	  else
	    this->root = new Node(volname, 0, NULL, this);
	  this->root->setDir();
	  this->root->addChild(fsroot);
	  if (this->bs->reserved != 0)
	    new ReservedSectors("reserved sectors", (uint64_t)(this->bs->reserved) * (uint64_t)this->bs->ssize, this->root, this);
	  if (this->bs->totalsize < this->parent->size())
	    new FileSystemSlack("file system slack", this->parent->size() - this->bs->totalsize, this->root, this);
	  this->fat->makeNodes(this->root);
	  std::vector<uint32_t>	clusters;
	  if (this->fat->freeClustersCount())
	    {
	      Node* unalloc = new Node("unallocated space", 0, this->root, this);
	      unalloc->setDir();
	      clusters = this->fat->listFreeClusters();
	      this->tree->processUnallocated(unalloc, clusters);	      
	    }
	  if (this->fat->badClustersCount())
	    {
	      Node* bad = new Node("bad clusters", 0, this->root, this);
	      bad->setDir();
	      clusters = this->fat->listBadClusters();
	      this->tree->processUnallocated(bad, clusters);
	    }
	  this->registerTree(this->parent, this->root);
	  if (this->carveunalloc)
	    this->tree->walk_free(this->root);
	}
    }
  catch(...)
    {
      throw("Fatfs module: error while processing");
    }
  return;
}

void		Fatfs::setContext(std::map<std::string, Variant_p > args) throw (std::string)
{
  std::map<std::string, Variant_p >::iterator	it;

  if ((it = args.find("file")) != args.end())
    this->parent = it->second->value<Node*>();
  else
    throw(std::string("Fatfs module: no file provided"));
  if ((it = args.find("meta_carve")) != args.end())
    this->carveunalloc = true;
  else
    this->carveunalloc = false;
  if ((it = args.find("check_slack")) != args.end())
    this->checkslack = true;
  else
    this->checkslack = false;
  return;
}

void		Fatfs::start(std::map<std::string, Variant_p > args)
{
  try
    {
      this->setContext(args);
      this->process();
    }
  catch(std::string e)
    {
      throw (e);
    }
  catch(vfsError e)
    {
      throw (e);
    }
  catch(envError e)
    {
      throw (e);
    }
  return ;
}

Fatfs::~Fatfs()
{
  //delete this->ctx;
}

Fatfs::Fatfs(): mfso("Fat File System")
{
  this->bs = new BootSector();
  this->fat = new FileAllocationTable();
  this->tree = new FatTree();
}
