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
 *  Christophe Malinge <cma@digital-forensic.org>
 *
 */

#include <stdio.h>
#include "reparsepoint.hpp"

AttributeReparsePoint::AttributeReparsePoint(Attribute &parent)
{
  _attributeHeader = new AttributeHeader(*(parent.attributeHeader()));
  _attributeResidentDataHeader = new AttributeResidentDataHeader(*(parent.residentDataHeader()));

  _readBuffer = parent.readBuffer();
  _attributeOffset = parent.attributeOffset();
  _bufferOffset = parent.bufferOffset();
  _offsetInRun = 0;
  _offsetRunIndex = 0;
}

AttributeReparsePoint::~AttributeReparsePoint()
{
  ;
}

void	AttributeReparsePoint::content()
{
  _data = (AttributeReparsePoint_t *)(_readBuffer + _bufferOffset +
				      _attributeResidentDataHeader->contentOffset);

  printf("\t\tFlags: 0x%x\n", _data->flags);
  printf("\t\tReparse data size: 0x%x\n", _data->reparseDataSize);
  printf("\t\tUnused: 0x%x\n", _data->unused);
  printf("\t\tOffset to target name: 0x%x\n", _data->targetNameOffset);
  printf("\t\tLength of target name: 0x%x\n", _data->targetNameLength);
  printf("\t\tOffset to print name of target: 0x%x\n", _data->targetPrintNameOffset);
  printf("\t\tLength of print name: 0x%x\n", _data->targetPrintNameLength);
}
