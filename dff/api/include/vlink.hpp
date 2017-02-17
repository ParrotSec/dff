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

#ifndef __VLINK_HPP__
#define __VLINK_HPP__

#include <string>
#include <map>
#include <vector>
#include <set>
#include <iostream>
#include <sys/types.h>
#include "node.hpp"

class VLink : public Node
{
private :
  Node* 			__linkedNode;
public :

  EXPORT uint32_t			id();
  EXPORT void				fileMapping(FileMapping *);
  EXPORT uint64_t			size();

  EXPORT std::string			linkPath();
  EXPORT std::string			linkName();
  EXPORT std::string			linkAbsolute();

  EXPORT bool				isFile();
  EXPORT bool				isDir();
  EXPORT bool				isLink();
  EXPORT bool				isVDir();
  EXPORT bool				isDeleted();

  EXPORT class fso*			fsobj();
  EXPORT class VFile*			open();

  EXPORT VLink(Node *linkedNode, Node* parent, std::string newname = "");
  EXPORT ~VLink();
  EXPORT  Node*				linkParent();
  EXPORT std::vector<class Node*>	linkChildren();
  EXPORT bool				linkHasChildren();
  EXPORT uint32_t			linkChildCount();
  EXPORT Node*				linkNode();

  EXPORT Attributes			dataType(void); 
  EXPORT Attributes			attributes(void);	
  EXPORT std::string			icon(void);
  EXPORT std::list<std::string>		compatibleModules(void);
  EXPORT bool				isCompatibleModule(std::string);
  EXPORT bool				setTag(std::string name);  
  EXPORT bool				setTag(uint32_t id);
  EXPORT bool				removeTag(std::string name);
  EXPORT bool				removeTag(uint32_t id);
  EXPORT bool				isTagged(std::string name);
  EXPORT bool				isTagged(uint32_t id);	
  EXPORT std::vector<Tag_p >		tags();
  EXPORT std::vector<uint32_t>		tagsId();
};

#endif
