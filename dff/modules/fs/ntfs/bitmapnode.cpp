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

#include "bitmapnode.hpp"

#include <sstream>

BitmapNode::BitmapNode(std::string Name, uint64_t size, Node *parent, Node *rootFile,
		       Ntfs *fsobj, uint64_t startingCluster, uint16_t clusterSize):
  Node(Name, size, parent, fsobj)
{
  _startingCluster = startingCluster;
  _clusterSize = clusterSize;
  _node = rootFile;
  setSize(size);
}

BitmapNode::~BitmapNode()
{
  ;
}

Attributes				BitmapNode::_attributes()
{
  Attributes	attr;

  dff::ScopedMutex	locker(dynamic_cast< Ntfs* >(this->fsobj())->_mutex);

  attr["Starting cluster"] = Variant_p(new Variant(this->_startingCluster));
  attr["Free clusters"] = Variant_p(new Variant(this->size() / this->_clusterSize));

  return attr;
}

void	BitmapNode::fileMapping(FileMapping *fm)
{
  if (size())
    fm->push(0, this->size(), this->_node, this->_startingCluster);
}
