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

#ifndef __STANDARDINFORMATION_HPP__
#define __STANDARDINFORMATION_HPP__

#include "common.hpp"
#include "attribute.hpp"

#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif

#ifdef WIN32
#define PACK
#else
#define PACK __attribute__((packed))
#endif

/**
 * $STANDARD_INFORMATION attribute
 */

/* SI_FLAG : Strandard_Information_Flag */
#define ATTRIBUTE_SI_FLAG_READ_ONLY		0x1
#define ATTRIBUTE_SI_FLAG_HIDDEN		0x2
#define ATTRIBUTE_SI_FLAG_SYSTEM		0x4
#define ATTRIBUTE_SI_FLAG_ARCHIVE		0x20
#define ATTRIBUTE_SI_FLAG_DEVICE		0x40
#define ATTRIBUTE_SI_FLAG_SHARPNORMAL		0x80
#define ATTRIBUTE_SI_FLAG_TEMPORARY		0x100
#define ATTRIBUTE_SI_FLAG_SPARSE_FILE		0x200
#define ATTRIBUTE_SI_FLAG_REPARSE_POINT		0x400
#define ATTRIBUTE_SI_FLAG_COMPRESSED		0x800
#define ATTRIBUTE_SI_FLAG_OFFLINE		0x1000
#define ATTRIBUTE_SI_FLAG_CONTENT_NOT_INDEXED	0x2000	// Content is not being indexed for faster searches
#define ATTRIBUTE_SI_FLAG_ENCRYPTED		0x4000

#define ATTRIBUTE_SI_FLAG_DIRECTORY		0x10000000
#define ATTRIBUTE_SI_FLAG_INDEX_VIEW		0x20000000

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeStandardInformation
{
  uint64_t	creationTime;		// Windows display/update those times
  uint64_t	fileAlteredTime;
  uint64_t	mftAlteredTime;
  uint64_t	fileAccessedTime;
  uint32_t	flags;			// See defines above
  uint32_t	maxNumberOfVersions;
  uint32_t	versionNumber;
  uint32_t	classID;
  uint32_t	ownerID;		// v3.0+
  uint32_t	securityID;		// v3.0+
  uint32_t	quotaCharged;		// v3.0+
  uint64_t	updateSequenceNumber;	// USN v3.0+
}		PACK AttributeStandardInformation_t;

class AttributeStandardInformation : public Attribute
{
public:
  AttributeStandardInformation(Attribute &);
  ~AttributeStandardInformation();
  void	content();
  AttributeStandardInformation_t	*data() { return _data; };

private:
  AttributeStandardInformation_t	*_data;
};

#endif
