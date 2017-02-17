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
 *  Solal J. <sja@digital-forensic.org>
 */

// \brief This class implements the virtual file system of the framework.

// The Virtual File System (VFS) is a central point of the framework.
// It permits to register nodes and browse them.

#ifndef __VFS_HPP__
#define __VFS_HPP__

#ifndef WIN32
  #include <stdint.h>
#elif _MSC_VER >= 1600
  #include <stdint.h>
#else
  #include "wstdint.h"
#endif
#include <vector>
#include <deque>
#include <list>
#include <set>

#include "eventhandler.hpp"
#include "export.hpp"
#include "exceptions.hpp"

class Node;
class fso;
class vfsError;
class VfsNode;

class VFS: public EventHandler
{  
private:
  EXPORT 	                VFS();
  EXPORT                        ~VFS();
  VFS&                          operator=(VFS&);
                                VFS(const VFS&);
  std::vector<fso*>	        __fsobjs;
  std::vector<Node*>	        __orphanednodes;
public:
  class Node*                   cwd;
  Node*		                root;
  std::set<class Node*>         Tree;
  EXPORT static VFS&            Get();
  EXPORT uint16_t	        registerFsobj(fso* fsobj) throw (vfsError);
  EXPORT uint64_t	        registerOrphanedNode(Node* n) throw (vfsError);
  EXPORT virtual void	        Event(event *e);
  EXPORT std::set<Node*>*       GetTree(void);
  EXPORT void 	                cd(Node *);
  EXPORT Node* 	                GetCWD(void);
  EXPORT Node*	                GetNode(std::string path);
  EXPORT Node*	                GetNode(std::string path, Node* where);
  EXPORT void		        AddNode(Node *parent, Node* head);
  EXPORT std::vector<fso*>	fsobjs();
  EXPORT uint64_t	        totalNodes();
  EXPORT Node*		        getNodeById(uint64_t id);
};

#endif
