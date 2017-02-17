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

#ifndef __READLINES_HH__
#define __READLINES_HH__


#include "fso.hpp"
#include "node.hpp"
#include <string>
#include <iostream>
#include <stdio.h>
#include "variant.hpp"
#include "vfs.hpp"

class readlines : public fso
{
private:
  Node*			__inode;
public:
  readlines();
  ~readlines();
  int32_t		vopen(Node* handle) {return 0;}
  int32_t 		vread(int fd, void *buff, unsigned int size) {return 0;}
  int32_t 		vclose(int fd) {return 0;}
  uint64_t 		vseek(int fd, uint64_t offset, int whence) {return 0;}
  int32_t		vwrite(int fd, void *buff, unsigned int size) { return 0; };
  uint32_t		status(void) {return 0;}
  uint64_t		vtell(int32_t fd) {return 0;}
  virtual void	start(std::map<std::string, Variant_p > args);
};
#endif
