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

#ifndef	__FATTREE_HPP__
#define __FATTREE_HPP__

#include "fatfs.hpp"
#include "node.hpp"
#include "fatnodes.hpp"
#include "vfile.hpp"
#include "entries.hpp"
#include "TwoThreeTree.hpp"


typedef struct	s_deletedItems
{
  Node*	node;
  ctx*	c;
}		deletedItems;

class FatTree
{
private:
  Node*				origin;
  uint64_t			allocount;
  uint64_t			processed;
  VFile*			vfile;
  class Fatfs*			fs;
  std::vector<deletedItems*>	deleted;
  std::map<uint32_t, Node*>	_slacknodes;
  std::set<uint32_t>		deletedUsedClusters;
  TwoThreeTree			*allocatedClusters;
  uint32_t			depth;
  void				makeSlackNodes();
  void				processDeleted();
  void				walkDeleted(uint32_t cluster, Node* parent);
  void				updateDeletedItems(ctx* c, Node* parent);
  void				updateAllocatedClusters(uint32_t cluster);
  Node*				allocNode(ctx* c, Node* parent);
  void				walk(uint32_t cluster, Node* parent);
  void				rootdir(Node* parent);
  std::string			__volname;

public:
  EntriesManager*		emanager;
  FatTree();
  ~FatTree();
  void		processUnallocated(Node* parent, std::vector<uint32_t> &clusters);
  void		walk_free(Node* parent);
  void		process(Node* origin, class Fatfs* fs, Node* parent);
  std::string	volname() {return __volname;}
};

#endif
