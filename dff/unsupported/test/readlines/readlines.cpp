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

#include "readlines.hpp"
#include "vfile.hpp"

readlines::readlines(): fso("readlines")
{
}

readlines::~readlines()
{
}


void readlines::start(std::map<std::string, Variant_p > args)
{
  std::map<std::string, Variant_p >::iterator	argit;
  std::string					line;
  VFile*					f;
  int32_t					i;

  if ((argit = args.find("file")) != args.end())
    {
      this->__inode = argit->second->value<Node*>();
      f = this->__inode->open();
      i = 0;
      while (f->readline().size())
	i++;
      std::cout << "total lines: " << i << std::endl;
    }
  else
    throw(envError("readlines module requires a file argument"));
}
