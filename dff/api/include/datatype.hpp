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
 *  Solal J. <sja@digital-forensic.org>
 */

#ifndef __DATATYPE_HPP__
#define __DATATYPE_HPP__

#ifndef WIN32
  #include <stdint.h>
#elif _MSC_VER >= 1600
  #include <stdint.h>
#else
  #include "wstdint.h"
#endif
#include <vector>
#include <map>
#include <list>
#include <stdexcept>

#include "threading.hpp"
#include "rc.hpp"
#include "variant.hpp"

class Node;

typedef std::map<std::string, RCPtr< class Variant > > Attributes;

class DataTypeHandler
{
public:
  EXPORT			DataTypeHandler(std::string);
  EXPORT  virtual 		~DataTypeHandler();
  EXPORT  virtual std::string	type(Node* ) = 0;
  std::string			name;
}; 

class DataTypeManager 
{
private:
  EXPORT					DataTypeManager();
  EXPORT					~DataTypeManager();
  DataTypeManager&				operator=(DataTypeManager&);
  						DataTypeManager(const DataTypeManager&);
  std::list<DataTypeHandler*>			handlers;
  uint32_t					idCounter;
  dff::map<Node*, dff::vector< uint32_t > >	nodeTypeId;
  dff::map<std::string, uint32_t >		uniq; 
  dff::map<uint32_t, std::string>		typeIdString;
  dff::map<uint32_t, DataTypeHandler*>		typeIdHandler; 
public:
  EXPORT static DataTypeManager* 		Get();
  EXPORT bool					registerHandler(DataTypeHandler*);
  EXPORT const std::map<std::string, uint32_t>&	foundTypes();
  EXPORT Attributes				type(Node*);
};

#endif
