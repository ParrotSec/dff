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

#include "exceptions.hpp"
#include "variant.hpp"
#include "node.hpp"
#include "datatype.hpp"

DataTypeManager* 	DataTypeManager::Get()
{
  static DataTypeManager single;
  return &single;
}

DataTypeManager::DataTypeManager()
{
  idCounter = 0;
}

DataTypeManager::~DataTypeManager()
{
}

bool		DataTypeManager::registerHandler(DataTypeHandler* handler)
{
  this->handlers.push_back(handler);
  return true;
}

Attributes	DataTypeManager::type(Node* node)
{
  std::list<DataTypeHandler* >::iterator	handler;
  Attributes					vars;
  
  if (node == NULL)
	return vars;
  
  if (this->nodeTypeId[node].empty())
    {
      for (handler = this->handlers.begin(); handler != this->handlers.end(); handler++)
	{
	  std::string res = (*handler)->type(node);
	  
	  uint32_t id = uniq[res];
	  if (id)
	    nodeTypeId[node].push_back(id);
	  else
	    {
	      uniq[res] = ++idCounter;
	      typeIdString[idCounter] = res;
	      typeIdHandler[idCounter] = *handler;
	      nodeTypeId[node].push_back(idCounter);
	    }
	} 
    }

  dff::vector< uint32_t > ids = nodeTypeId[node];
  
  unsigned int count = 0;
  unsigned int size = ids.size();
  DataTypeHandler* dthptr;
  while (count != size)
    {
      uint32_t id = ids[count];
      if ((dthptr = typeIdHandler[id]) != NULL)
	vars[dthptr->name] = new Variant(typeIdString[id]);
      count++;
    }
  return vars;
}

const std::map<std::string, uint32_t>&	DataTypeManager::foundTypes()
{
  return (this->uniq.getInternals());
}

DataTypeHandler::DataTypeHandler(std::string hname)
{
  DataTypeManager* 	dataTypeManager =  DataTypeManager::Get();

  this->name = hname;
  dataTypeManager->registerHandler(this);
}

DataTypeHandler::~DataTypeHandler()
{

}

