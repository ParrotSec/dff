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
#include "standardinformation.hpp"

AttributeStandardInformation::AttributeStandardInformation(Attribute &parent)
{
  _attributeHeader = new AttributeHeader(*(parent.attributeHeader()));
  _attributeResidentDataHeader = new AttributeResidentDataHeader(*(parent.residentDataHeader()));

  _readBuffer = parent.readBuffer();
  _attributeOffset = parent.attributeOffset();
  _bufferOffset = parent.bufferOffset();
  _mftEntrySize = parent.mftEntrySize();
  _indexRecordSize = parent.indexRecordSize();
  _sectorSize = parent.sectorSize();
  _clusterSize = parent.clusterSize();

  _offsetInRun = 0;
  _offsetRunIndex = 0;

  _data = new AttributeStandardInformation_t(*((AttributeStandardInformation_t *)
					       (_readBuffer + _bufferOffset +
						_attributeResidentDataHeader->contentOffset)));

  //  content();
}

AttributeStandardInformation::~AttributeStandardInformation()
{
  delete _data;
  delete _attributeHeader;
  delete _attributeResidentDataHeader;
}

void		AttributeStandardInformation::content()
{
  struct tm	*date;
  std::string	dateString;

  //  _data = (AttributeStandardInformation_t *)(_readBuffer + _bufferOffset +
  //					   _attributeResidentDataHeader->contentOffset);

  setDateToString(_data->creationTime, &date, &dateString, true);
#if __WORDSIZE == 64
  printf("\tSI Creation time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->creationTime);
#else
  printf("\tSI Creation time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->creationTime);
#endif
  setDateToString(_data->fileAlteredTime, &date, &dateString, true);
#if __WORDSIZE == 64
  printf("\tSI File altered time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->fileAlteredTime);
#else
  printf("\tSI File altered time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->fileAlteredTime);
#endif
  setDateToString(_data->mftAlteredTime, &date, &dateString, true);
#if __WORDSIZE == 64
  printf("\tSI MFT altered time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->mftAlteredTime);
#else
  printf("\tSI MFT altered time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->mftAlteredTime);
#endif
  setDateToString(_data->fileAccessedTime, &date, &dateString, true);
#if __WORDSIZE == 64
  printf("\tSI File accessed time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->fileAccessedTime);
#else
  printf("\tSI File accessed time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->fileAccessedTime);
#endif
  printf("\tFlags 0x%x\n", _data->flags);
  if (_data->flags & ATTRIBUTE_SI_FLAG_READ_ONLY) {
    printf("\t\tRead only\n");
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_HIDDEN) {
    printf("\t\tHidden\n");
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_SYSTEM) {
    printf("\t\tSystem\n");
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_ARCHIVE) {
    printf("\t\tArchive\n");
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_DEVICE) {
    printf("\t\tDevice\n");
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_SHARPNORMAL) {
    printf("\t\t#Normal\n");
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_TEMPORARY) {
    printf("\t\tTemporary\n");
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_SPARSE_FILE) {
    printf("\t\tSparse\n");
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_REPARSE_POINT) {
    printf("\t\tReparse point\n");
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_COMPRESSED) {
    printf("\t\tCompressed\n");
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_OFFLINE) {
    printf("\t\tOffline\n");
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_CONTENT_NOT_INDEXED) {
    printf("\t\tContent is not being indexed for faster searches\n");
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_ENCRYPTED) {
    printf("\t\tEncrypted\n");
  }
  if (!(_data->flags & ATTRIBUTE_SI_FLAG_READ_ONLY)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_HIDDEN)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_SYSTEM)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_ARCHIVE)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_DEVICE)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_SHARPNORMAL)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_TEMPORARY)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_SPARSE_FILE)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_REPARSE_POINT)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_COMPRESSED)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_OFFLINE)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_CONTENT_NOT_INDEXED)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_ENCRYPTED)) {
    printf("\tunknown\n");
  }
  if (_data->maxNumberOfVersions) {
    printf("\tMaximum number of versions 0x%x\n", _data->maxNumberOfVersions);
  }
  else {
    printf("\tMaximum number of versions not used\n");
  }
  if (_data->versionNumber) {
    printf("\tVersion number 0x%x\n", _data->versionNumber);
  }
  else {
    printf("\tVersion number not used\n");
    printf("\tClass ID 0x%x\n", _data->classID);
    printf("\tOwner ID 0x%x\n", _data->ownerID);
    printf("\tSecurity ID 0x%x\n", _data->securityID);
    printf("\tQuota charged 0x%x\n", _data->quotaCharged);
#if __WORDSIZE == 64
    printf("\tUpdate sequence number (USN) 0x%lx\n", _data->updateSequenceNumber);
#else
    printf("\tUpdate sequence number (USN) 0x%llx\n", _data->updateSequenceNumber);
#endif
  }
}

