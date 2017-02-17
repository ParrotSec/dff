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
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

#include <iostream>
#include <vector>

#include "indexer.hpp"
#include "variant.hpp"
 
Indexer::Indexer()
  : mfso("Indexer"), __node(NULL), __index(NULL)
{
}
 
Indexer::~Indexer()
{
}

void    Indexer::start(std::map<std::string, Variant *> args)
{
  try
    {
      std::map<std::string, Variant *>::iterator it;
      it = args.find("node");
      if (it == args.end())
	{
	  std::cerr << "Cannot load 'node' argument. Exiting module." << std::endl;
	  return ;
	}
      this->__node = it->second->value<Node*>();

      it = args.find("index");
      if (it == args.end())
	{
	  std::cerr << "Cannot load 'index' argument. Exiting module." << std::endl;
	  return ;
	}
      std::string path = it->second->value<string>();

      __index = new Index(path);
      if (!__index->createIndex())
	{
	  std::cerr << "Could not create index. Modules 'indexer' will stop."
		    << std::endl;
	  this->stateinfo = std::string("An error occured while creating the index.");
	  return ;
	}
      this->__recurseNode(this->__node);
      this->__index->closeIndex();
      delete __index;
    }
  catch(vfsError & e)
    {
      this->stateinfo = e.error;
    }
  return ;
}

void	Indexer::__recurseNode(Node * node)
{
  if (!node)
    return ;
  if (node->size() && node->isFile())
    this->__index->indexData(node);
  if (node->hasChildren()) // if the node has children, get all of them
    {
      std::vector<class Node *>	nodes_list = node->children();
      std::vector<class Node *>::iterator   it, end;
      
      end = nodes_list.end();
      for (it = nodes_list.begin(); it != end; it++)
	this->__recurseNode(*it);
    }
}
