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

#ifndef __SECURITYDESCRIPTOR_HPP__
#define __SECURITYDESCRIPTOR_HPP__

#include "common.hpp"
#include "attribute.hpp"


#ifdef WIN32
#define PACK
#else
#define PACK __attribute__((packed))
#endif

/**
 * $SECURITY_DESCRIPTOR attribute
 */

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_AttributeSecurityDescriptor
{
  uint8_t	todo;
}		PACK AttributeSecurityDescriptor_t;

class AttributeSecurityDescriptor : public Attribute
{
public:
  AttributeSecurityDescriptor(Attribute &);
  ~AttributeSecurityDescriptor();
  void		content();

private:
  AttributeSecurityDescriptor_t	*_data;
};

#endif
