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
 *  Solal Jacob <sja@digital-forensic.org>
 */

#include "shm.hpp"

ShmNode::ShmNode(std::string name, uint64_t size, fso* fsobj): Node(name, size, NULL, fsobj)
{
  this->setFile();
}

ShmNode::~ShmNode()
{
} 

void	ShmNode::setId(uint32_t id)
{
  this->__id = id;
}

uint32_t	ShmNode::id()
{
  return this->__id;
}


Shm::Shm(): fso("shm")
{
  this->__fdm = new FdManager();
}

Shm::~Shm()
{
}

void	Shm::start(std::map<std::string, Variant*> args)
{
  std::map<std::string, Variant*>::iterator it;
  Node*		parent;
  std::string	filename;
  Node*		node;

  if ((it = args.find("parent")) != args.end())
    parent = it->second->value<Node*>();
  else
    throw vfsError("shm requires < parent > argument");
  if ((it = args.find("filename")) != args.end())
    filename = it->second->value<std::string>();
  else
    throw vfsError("shm requires < filename > argument");
  node = this->addnode(parent, filename);
  std::string n = "file " + node->absolute() + " created\n";
  this->res["result"] = new Variant(n);
  return ;
}

Node*	Shm::addnode(Node* parent, std::string filename)
{
  ShmNode*	node;
  uint32_t	id;
  pdata*	data;
  
  node = new ShmNode(filename, 0, this);
  id = this->__nodesdata.size();
  node->setId(id);
  data = new pdata;
  data->buff = NULL;
  data->len = 0;
  this->__nodesdata.push_back(data);
  this->registerTree(parent, node);
  return node;
}

int32_t	Shm::vopen(Node *node)
{
  fdinfo*	fi;
  int32_t	fd;

  if (node == NULL)
    throw vfsError("[SHM] vopen() provided node is NULL\n"); 
  fi = new fdinfo;
  fi->node = node;
  fi->offset = 0;
  fd = this->__fdm->push(fi);
  return (fd);
}

int32_t		Shm::vread(int32_t fd, void *buff, uint32_t size)
{
  fdinfo*	fi;
  ShmNode*	node;
  uint32_t	id;
  pdata*	data;
  std::string	err;

  try
    {
      fi = this->__fdm->get(fd);
      node = dynamic_cast<ShmNode*>(fi->node);
      id = node->id();
      if (id > this->__nodesdata.size())
	throw vfsError("[SHM] vread() node id does not exist\n");
      data = this->__nodesdata[id];
      if ((node->size() == 0) || (data->len == 0) || (data->len < fi->offset) || (node->size() < fi->offset))
	throw vfsError("[SHM] vread() either file size is 0 or offset is too high\n");
      if ((data->len - fi->offset) < size)
	size = data->len - fi->offset;
      memcpy(buff, (char *)data->buff + fi->offset, size);
      fi->offset += size;
      return (size);
    }
  catch (const std::exception& e)
    {
      err = std::string("[SHM] vread() cannot read file\n") + e.what();
      throw vfsError(err);
    }
  catch (vfsError e)
    {
      throw vfsError("[SHM] vread() cannot read file\n" + e.error);
    }
}

int32_t		Shm::vwrite(int32_t fd, void *buff, uint32_t size) 
{
  fdinfo*	fi;
  ShmNode*	node;
  uint32_t	id;
  pdata*	data;
  std::string	err;

  try
    {
      fi = this->__fdm->get(fd);
      node = dynamic_cast<ShmNode*>(fi->node);
      id = node->id();
      if (id > this->__nodesdata.size())
	throw vfsError("[SHM] vwrite() node id does not exist\n");
      data = this->__nodesdata[id];
      if (data->len < fi->offset)
	throw vfsError("[SHM] vwrite() offset is too high\n");
      if (data->len == 0)
	{
	  data->buff = new char[size];
	  data->len = size;
	}
      else if (data->len < (fi->offset + size))
	{
	  size = (uint32_t)(fi->offset + size - data->len);
	  data->buff = realloc(data->buff, sizeof(char) * (data->len + size));
	  data->len += size;
	}
      memcpy((char*)data->buff + fi->offset, buff, size);
      fi->offset += size;
      node->setSize(data->len);
      return size;
    }
  catch (const std::exception& e)
    {
      err = std::string("[SHM] vwrite() cannot write file\n") + e.what();
      throw vfsError(err);
    }
  catch (vfsError e)
    {
      throw vfsError("[SHM] vwrite() cannot write file\n" + e.error);
    }
}

uint64_t	Shm::vseek(int32_t fd, uint64_t offset, int32_t whence)
{
  fdinfo*	fi;
  ShmNode*	node;
  uint32_t	id;
  std::string	err;

  try
    {
      fi = this->__fdm->get(fd);
      node = dynamic_cast<ShmNode*>(fi->node);
      id = node->id();
      if (id > this->__nodesdata.size())
	throw vfsError("[SHM] vseek() node id does not exist\n");
      if (whence == 0)
	if (offset < node->size())
	  fi->offset = offset;
	else
	  throw vfsError("[SHM] vseek() offset is too high\n");
      else if (whence == 1)
	if (fi->offset + offset < node->size())
	  fi->offset += offset;
	else
	  throw vfsError("[SHM] vseek() offset is too high\n");
      else if (whence == 2)
	fi->offset = node->size();
      return (fi->offset);
    }
  catch (const std::exception& e)
    {
      err = std::string("[SHM]: vseek() cannot seek\n") + e.what();
      throw vfsError(err);
    }
  catch (vfsError e)
    {
      throw vfsError("[SHM] vseek() cannot seek\n" + e.error);
    }
}

int32_t		Shm::vclose(int32_t fd)
{
  std::string err;

  try
    {
      this->__fdm->remove(fd);
      return (0);
    }
  catch (const std::exception& e)
    {
      err = std::string("[SHM] vclose() error while closing fd\n") + e.what();
      throw vfsError(err);
    }
}

uint64_t	Shm::vtell(int32_t fd)
{
  fdinfo*	fi;
  std::string	err;

  try
    {
      fi = this->__fdm->get(fd);
      return (fi->offset);
    }
  catch (const std::exception& e)
    {
      err = std::string("[SHM] vtell() can not tell offset\n") + e.what();
      throw vfsError(err);
    }
}

uint32_t	Shm::status(void)
{
  return (0);
}

