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

#include "fso.hpp"

fso::fso(std::string name)
{
  this->name = name;
  this->stateinfo = "";
  this->__uid = VFS::Get().registerFsobj(this);
  this->__parent = NULL;
}

fso::~fso()
{
}

uint64_t	fso::nodeCount()
{
  return this->__nodes.size();
}

std::vector<fso*>	fso::children()
{
  return this->__children;
}

bool	fso::hasChildren()
{
  return this->__children.size() > 0;
}

uint32_t	fso::childCount()
{
  return this->__children.size();
}

void		fso::setParent(fso* parent)
{
  if (parent != NULL)
    {
      this->__parent = parent;
    }
}

fso*	fso::parent()
{
  return this->__parent;
}

void		fso::addChild(fso* child)
{
  if (child != NULL)
    {
      child->setParent(this);
      this->__children.push_back(child);
    }
}

void	fso::registerTree(Node* parent, Node* head)
{
  event*  e = new event;
  e->value = Variant_p(new Variant(head));
  fso*	pfsobj;

  if (((pfsobj = parent->fsobj()) != NULL) && (pfsobj != this))
    pfsobj->addChild(this);
  //AttributesIndexer::Get().registerAttributes(head);
  parent->addChild(head);
  VFS::Get().notify(e);
}

std::vector<Node*>	fso::nodes()
{
  return this->__nodes;
}

uint16_t	fso::uid()
{
  return this->__uid;
}

Node*		fso::getNodeById(uint64_t id)
{
  uint64_t	nid;
  uint16_t	fsoid;

  fsoid = id >> 48;
  if (fsoid == this->__uid)
    {
      nid = id & 0x0000ffffffffffffLL;
      if (nid < this->__nodes.size())
	return this->__nodes[nid];
      else
	return NULL;
    }
  else
    return NULL;
}

uint64_t	fso::registerNode(Node* n)
{
  uint64_t	nid;

  nid = this->__uid;
  nid = nid << 48;
  this->__nodes.push_back(n);
  nid |= this->__nodes.size() - 1;
  return nid;
}
