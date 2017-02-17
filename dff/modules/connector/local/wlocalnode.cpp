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
 *  Christophe Malinge <cma@digital-forensic.org>
 */

#include "wlocalnode.hpp"
#include <windows.h>

WLocalNode::WLocalNode(std::string Name, uint64_t size, Node* parent, fso* fsobj, uint8_t type, std::string origPath): Node(Name, size, parent, fsobj)
{
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
  this->originalPath = origPath;
}

WLocalNode::~WLocalNode()
{
}


Attributes		WLocalNode::_attributes(void)
{
	WIN32_FILE_ATTRIBUTE_DATA	info;
	Attributes					attr;
   
	
	attr["original path"] = Variant_p(new Variant(this->originalPath));
    if(!GetFileAttributesExA(this->originalPath.c_str(), GetFileExInfoStandard, &info))
		return attr;
	
    attr["modified"] = Variant_p(new Variant(this->wtimeToVtime(&(info.ftLastWriteTime))));
    attr["accessed"] = Variant_p(new Variant(this->wtimeToVtime(&(info.ftLastAccessTime))));
    attr["creation"] = Variant_p(new Variant(this->wtimeToVtime(&(info.ftCreationTime))));
    return attr;
}


vtime*				WLocalNode::wtimeToVtime(FILETIME *tt)
{
	SYSTEMTIME	stUTC;
	vtime*	vt = new vtime;

	if (tt == NULL)
		return vt;
		
	if (FileTimeToSystemTime(tt, &stUTC) == 0)
		return vt;

  	vt->year = stUTC.wYear;
	vt->month = stUTC.wMonth;
	vt->day = stUTC.wDay;
	vt->hour = stUTC.wHour;
	vt->minute = stUTC.wMinute;
	vt->second = stUTC.wSecond;
	vt->dst = 0;
	vt->wday = stUTC.wDayOfWeek;
	vt->yday = 0;
	vt->usecond = stUTC.wMilliseconds;

	return vt;
}
