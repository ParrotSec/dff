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

#ifndef __MEM_HH__
#define __MEM_HH__

#include "mfso.hpp"
#ifndef WIN32
#include <dlfcn.h>
#endif
#include <stdlib.h>
#include <string>
#include <stdlib.h>
#include <list>
#include <vector>
#include <map>
#include "variant.hpp"
#include "exceptions.hpp"
#include "vfs.hpp"
#include "vfile.hpp"
#include "vlink.hpp"
#include "node.hpp"

class ShmNode: public Node
{
private:
  uint32_t	__id;
public:
  ShmNode(std::string name, uint64_t size, fso* fsobj);
  ~ShmNode();
  void		setId(uint32_t id);
  uint32_t	id();
};

class Shm: public fso
{
private:
  std::vector<pdata *> 		__nodesdata;
  FdManager*			__fdm;
  class Node*   		__root;
public:
  Shm();
  ~Shm();
  Node*			addnode(Node* parent, std::string filename);
  virtual void		start(std::map<std::string, Variant*> args);
  virtual int32_t	vopen(Node* node);
  virtual int32_t	vread(int32_t fd, void *buff, uint32_t size);
  virtual int32_t	vwrite(int32_t fd, void *buff, uint32_t size);
  virtual int32_t	vclose(int32_t fd);
  virtual uint64_t	vseek(int32_t fd, uint64_t offset, int32_t whence); 
  virtual uint64_t	vtell(int32_t fd);
  virtual uint32_t	status(void);
};

#endif 
