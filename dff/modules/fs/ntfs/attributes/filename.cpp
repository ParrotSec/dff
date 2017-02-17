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
#include <unicode/unistr.h>
#include "filename.hpp"

AttributeFileName::AttributeFileName(Attribute &parent)
{
  uint8_t	*name;
  UnicodeString	us;
  

  _attributeHeader = new AttributeHeader(*(parent.attributeHeader()));
  _attributeResidentDataHeader = new AttributeResidentDataHeader(*(parent.residentDataHeader()));

  _readBuffer = parent.readBuffer();
  _attributeOffset = parent.attributeOffset();
  _bufferOffset = parent.bufferOffset();
  _offsetInRun = 0;
  _offsetRunIndex = 0;


  _data = new AttributeFileName_t(*((AttributeFileName_t *)(_readBuffer + _bufferOffset +
							    _attributeResidentDataHeader->contentOffset)));
  name = (_readBuffer + _bufferOffset + ATTRIBUTE_FN_SIZE +
	  _attributeResidentDataHeader->contentOffset);

  us = UnicodeString((char*)name, _attributeResidentDataHeader->contentSize - ATTRIBUTE_FN_SIZE, "UTF-16LE");
  us.toUTF8String(_filename);
  //DEBUG(INFO, "found filename: %s\n", _filename.c_str());
  //  content();
}

AttributeFileName::~AttributeFileName()
{
  ;
}

std::string	AttributeFileName::getFileName()
{
  return _filename;
}

void	AttributeFileName::content()
{
  struct tm		*date;
  std::string		dateString;
  
#if __WORDSIZE == 64
  printf("\tParent directory fileref 0x%.16lx\n", _data->parentDirectoryFileReference);
  printf("\tReal size of file %ld bytes\n", _data->realSizeOfFile);
#else
  printf("\tParent directory fileref 0x%.16llx\n", _data->parentDirectoryFileReference);
  printf("\tReal size of file %lld bytes\n", _data->realSizeOfFile);
#endif
  printf("\tFilename data: %s\n", _filename.c_str());
  setDateToString(_data->fileCreationTime, &date, &dateString, true);
#if __WORDSIZE == 64
  printf("\tFile creation time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->fileCreationTime);
#else
  printf("\tFile creation time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->fileCreationTime);
#endif
  setDateToString(_data->fileModificationTime, &date, &dateString, true);
#if __WORDSIZE == 64
  printf("\tFile modification time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->fileModificationTime);
#else
  printf("\tFile modification time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->fileModificationTime);
#endif
  setDateToString(_data->mftModificationTime, &date, &dateString, true);
#if __WORDSIZE == 64
  printf("\tMFT modification time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->mftModificationTime);
#else
  printf("\tMFT modification time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->mftModificationTime);
#endif
  setDateToString(_data->fileAccessTime, &date, &dateString, true);
#if __WORDSIZE == 64
  printf("\tFile access time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->fileAccessTime);
#else
  printf("\tFile access time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->fileAccessTime);
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
    printf("\t\tunknown\n");
  }
  printf("\tReparse value 0x%x\n", _data->reparseValue);
  printf("\tName length 0x%x\n", _data->nameLength);
  printf("\tNamespace is 0x%x corresponding to:\n", _data->nameSpace);
  if (_data->nameSpace & ATTRIBUTE_FN_NAMESPACE_POSIX) {
    printf("\t\tPOSIX (name is case sensitive, allows all Unicode chars except '/' and NULL)\n");
  }
  if (_data->nameSpace & ATTRIBUTE_FN_NAMESPACE_WIN32_AND_DOS) { 
    printf("\t\tWin32 and DOS (original name fits in DOS namespace)\n");
  }
  if (_data->nameSpace & ATTRIBUTE_FN_NAMESPACE_WIN32) { 
    printf("\t\tWin32 (name is case insensitive, allows most Unicode chars except '/', '\', ':', '>', '<' and '?')\n");
  }
  if (_data->nameSpace & ATTRIBUTE_FN_NAMESPACE_DOS) { 
    printf("\t\tDOS (name is case insensitive, upper case, no special chars, name length <= 8, extension length <= 3\n");
  }
}

