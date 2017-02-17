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

#ifndef __FILENAME_HPP__
#define __FILENAME_HPP__

#include "common.hpp"
#include "attribute.hpp"
#include "standardinformation.hpp" // need flags
#include <sstream>

#ifdef WIN32
#define PACK
#else
#define PACK __attribute__((packed))
#endif

/**
 * $FILE_NAME attribute
 *  Used in two places :
 *   - As MFT entry : does not contain any essential information
 *   - As directory index : does contain essential information
 */

#define ATTRIBUTE_FN_NAMESPACE_POSIX		0x0
#define ATTRIBUTE_FN_NAMESPACE_WIN32_AND_DOS	0x3
#define ATTRIBUTE_FN_NAMESPACE_WIN32		0x1
#define ATTRIBUTE_FN_NAMESPACE_DOS		0x2

#define ATTRIBUTE_FN_SIZE	66

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeFileName
{
  uint64_t	parentDirectoryFileReference;	// Windows displays/update times
  uint64_t	fileCreationTime;		// from $STANDARD_INFORMATION,
  uint64_t	fileModificationTime;		// not these ones
  uint64_t	mftModificationTime;
  uint64_t	fileAccessTime;
  uint64_t	allocatedSizeOfFile;
  uint64_t	realSizeOfFile;
  uint32_t	flags;			// Same as for $STANDARD_INFORMATION
  uint32_t	reparseValue;
  uint8_t	nameLength;		// Essential in directory index
  uint8_t	nameSpace;		// Essential in directory index
  //uint8_t	*name			// Essential in directory index
}		PACK AttributeFileName_t;


class AttributeFileName : public Attribute
{
public:
  AttributeFileName(Attribute &);
  ~AttributeFileName();
  void		content();
  std::string	getFileName();
  void		appendToFileName(std::string);
  AttributeFileName_t	*data() { return _data; };

private:
  std::string	_filename;
  AttributeFileName_t	*_data;
};

#endif
