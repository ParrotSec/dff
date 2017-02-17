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

#include "ulocalnode.hpp"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


Attributes	ULocalNode::_attributes()
{
  struct stat*	st;
  Attributes 	vmap;

  vmap["original path"] =  Variant_p(new Variant(this->originalPath));
  if ((st = this->localStat()) != NULL)
    {
      vmap["uid"] =  Variant_p(new Variant(st->st_uid));
      vmap["gid"] =  Variant_p(new Variant(st->st_gid));
      vmap["inode"] = Variant_p(new Variant(st->st_ino));
      vmap["modified"] = Variant_p(new Variant(this->utimeToVtime(&(st->st_mtime))));
      vmap["accessed"] = Variant_p(new Variant(this->utimeToVtime(&(st->st_atime))));
      vmap["changed"] = Variant_p(new Variant(this->utimeToVtime(&(st->st_ctime))));
      free(st);
    }
  return vmap;
}


struct stat*	ULocalNode::localStat(void)
{
  std::string	file;
  struct stat* 	st;

  st = (struct stat*)malloc(sizeof(struct stat));
  if (lstat(this->originalPath.c_str(), st) != -1)
    return st;
  else
    {
      free(st);
      return NULL;
    }
}

vtime*		ULocalNode::utimeToVtime(time_t* tt) 
{
  struct tm*	t;
  vtime	*vt = new vtime;

  if (tt != NULL)
    {
      if ((t = gmtime(tt)) != NULL)
	{
	  vt->year = t->tm_year + 1900;
	  vt->month = t->tm_mon + 1;
	  vt->day = t->tm_mday;
	  vt->hour = t->tm_hour;
	  vt->minute = t->tm_min;
	  vt->second = t->tm_sec;
	  vt->dst = t->tm_isdst;
	  vt->wday = t->tm_wday;
	  vt->yday = t->tm_yday;
	  vt->usecond = 0;
	}
    }
   return vt;
}


ULocalNode::ULocalNode(std::string Name, uint64_t size, Node* parent, local* fsobj, uint8_t type, std::string origPath): Node(Name, size, parent, fsobj)
{
  this->originalPath = origPath;
  switch (type)
    {
    case DIR:
      this->setDir();
      break;
    case FILE:
      this->setFile();
      break;
    default:
      break;
    }
}

ULocalNode::~ULocalNode()
{
}

