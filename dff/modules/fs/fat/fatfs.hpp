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

#ifndef __FATFS_HPP__
#define __FATFS_HPP__

#include <map>
#include "variant.hpp"
#include "mfso.hpp"
#include "bootsector.hpp"
#include "fat.hpp"
#include "fattree.hpp"
#include "node.hpp"

class Fatfs : public mfso
{
public:
  Fatfs();
  ~Fatfs();
  Node*			root;
  Node*			parent;
  bool			carveunalloc;
  bool			checkslack;
  class FatTree*	tree;
  class BootSector*	bs;
  class FileAllocationTable*	fat;
  VFile*		vfile;
  virtual void		start(std::map<std::string, Variant_p > args);
  void			setContext(std::map<std::string, Variant_p > args) throw (std::string);
  void			process();
};

#endif
