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
 *  Solal J. <sja@digital-forensic.org>
 */
#include "cache.hpp"
#include "fso.hpp"
#include "vfile.hpp"
#include "datatype.hpp"
#include "tags.hpp"
#include "confmanager.hpp"
#include "node.hpp"

Node::Node()
{
}

Node::Node(std::string name, uint64_t size, Node* parent, fso* fsobj)
{
  this->__common_attributes = 0;
  this->__childcount = 0;
  this->__at = 0;
  this->__fsobj = fsobj;
  this->__size = size;
  this->__parent = parent;
  if (this->__fsobj != NULL)
    this->__uid = this->__fsobj->registerNode(this);
  else if (parent != NULL)
  {
    this->__uid = VFS::Get().registerOrphanedNode(this);
  }
  else
    this->__uid = 0;
  if (this->__parent != NULL)
  {
    this->__parent->addChild(this);
  }
  this->__name = name;
  this->__tags = 0;
}

Node::~Node()
{
  if (!this->__children.empty())
    this->__children.clear();
}

void            Node::fileMapping(FileMapping *)
{
}

void	        Node::setFsobj(fso *obj)
{
  this->__fsobj = obj;
}

fso*		Node::fsobj()
{
  return this->__fsobj;
}

uint64_t	Node::uid()
{
  return this->__uid;
}

uint32_t	Node::at()
{
  return this->__at;	
}

void	 	Node::setId(uint32_t id)
{
  this->__id = id;
}

uint32_t	Node::id()
{
  return this->__id;
}

std::string	Node::name()
{
  return this->__name;
}

std::string	Node::extension()
{
  size_t	dpos;
  std::string	ext;
  
  if ((dpos = this->__name.rfind(".")) != std::string::npos)
    ext = this->__name.substr(dpos+1);
  return ext;
}

std::string	Node::absolute()
{
  return this->path() + this->__name;
}

void		Node::setParent(Node *parent)
{
  if (parent != NULL)
    {
      this->__parent = parent;
      //this->__parent->addChild(this);
    }
}

Node*		Node::parent()
{
  return this->__parent;
}

bool		Node::addChild(class Node *child)
{
  if (child != NULL)
  {
    child->setParent(this);
    child->__at = this->__childcount; 
    this->__children.push_back(child);
    this->__childcount++;
    return true;
  }
  return false;
}

std::vector<class Node*>	Node::children()
{
  return this->__children;
}

std::string	Node::path()
{
  std::string path;
  Node	*tmp;

  if (this->__parent == this)
    return "";
  path = "";
  tmp = this->__parent;
  if (!tmp)
    {
      path = "";
      return path;
    }
  while ((tmp->__parent != tmp) && (tmp->__parent != NULL))
    {
      path = tmp->name() + "/" + path;
      tmp = tmp->parent();
    }
  if (tmp->__parent == tmp)
    path = "/" + path;
  return path;
}

bool            Node::hasChildren()
{
  if (this->__childcount > 0)
    return true;
  else
    return false;
}

uint32_t	Node::childCount()
{
  return this->__childcount;
}

uint64_t	Node::totalChildrenCount(uint32_t depth)
{
  uint64_t	totalsub;
  size_t	i;

  totalsub = this->__childcount;
  if (depth != 0)
    {
      for (i = 0; i != this->__children.size(); i++)
	if (this->__children[i]->hasChildren())
	  totalsub += this->__children[i]->totalChildrenCount(depth-1);
    }
  return totalsub;
}

void		Node::setSize(uint64_t size)
{
  this->__size = size;
}

uint64_t                	Node::size()
{
  return this->__size;
}

void		Node::setFile()
{
  if (!this->isDir())
    this->__common_attributes |= ISFILE;
  else
    throw("attribute ISDIR already setted");
}

bool				Node::isFile()
{
  if ((this->__common_attributes & ISFILE) == ISFILE)
    return true;
  else
    return false;
}

void		Node::setDir()
{
  if (!this->isFile())
    this->__common_attributes |= ISDIR;
  else
    throw("attribute ISFILE already setted");
}

bool				Node::isDir()
{
  if ((this->__common_attributes & ISDIR) == ISDIR)
    return true;
  else
    return false;
}

void		Node::setLink()
{
  this->__common_attributes |= ISLINK;
}

bool		Node::isLink()
{
  if ((this->__common_attributes & ISLINK) == ISLINK)
    return true;
  else
    return false;
}

bool		Node::isVDir()
{
  if (this->isFile() && this->hasChildren())
    return true;
  else
    return false;
}

void		Node::setDeleted()
{
  this->__common_attributes |= ISDELETED;
}

bool		Node::isDeleted()
{
  if ((this->__common_attributes & ISDELETED) == ISDELETED)
    return true;
  else
    return false;
}


VFile*		Node::open()
{
  int32_t	fd;
  VFile		*temp;

  if (this->__fsobj == NULL)
    throw vfsError("Can't Open file");
  try
    {
      if ((fd = this->__fsobj->vopen(this)) >= 0)
	{
	  temp = new VFile(fd, this->__fsobj, this);
	  return (temp);
	}
      throw vfsError("Can't Open file");
    }
  catch (vfsError e)
    {
      throw vfsError("Node::open(void) throw\n" + e.error);
    }
}

std::string     Node::icon(void)
{
  if (!(this->hasChildren()))
  {
    if (this->isDir())
      return (":folder_128.png");
    if (!(this->size()))
      return (":folder_empty_128.png");
    return (":folder_empty_128.png");
  }
  else
  {
    if (this->size() != 0)
      return (":folder_documents_128.png");
    else
      return (":folder_128.png");
  }
}

Attributes	Node::dataType(void) 
{
  Attributes	types;

  class DataTypeManager*	typeDB = DataTypeManager::Get();
  types = typeDB->type(this);
  return types;
}

Attributes	Node::_attributes(void)
{
  Attributes attr;
  return (attr);
}

uint64_t        Node::_attributesState(void)
{
  return (0);
}

Attributes	Node::fsoAttributes()
{
  try 
  {
    return AttributeCache::instance().find(this, this->_attributesState());
  }
  catch (std::string)
  {
    Attributes attributes;
    try 
    {
      attributes =  this->_attributes();
      AttributeCache::instance().insert(this, attributes, this->_attributesState());
    }
    catch (...)
    {
      std::cout << this->absolute() << " fso attribute  raise error\n" << std::endl;
    }
    return attributes;
  }
}

Attributes	Node::dynamicAttributes()
{
  Attributes	attr;
  Variant*	vptr;

  size_t        size = this->__attributesHandlers.count();

  if (size == 0)
    return attr;
  try
  {
    return DynamicAttributesCache::instance().find(this, this->__attributesHandlers.state());
  }
  catch (std::string)
  {
    std::set<AttributesHandler*>& handlers = this->__attributesHandlers.handlers();
    std::set<AttributesHandler*>::iterator handler;
 
    for (handler = handlers.begin(); handler != handlers.end(); handler++)
    {
      try
      {
        if ((vptr = new Variant((*handler)->attributes(this))) != NULL)
          attr[(*handler)->name()] = Variant_p(vptr); 
      }
      catch (...)
      {
        std::cout << this->absolute() << " attribute handler " << (*handler)->name() << " raise error\n" << std::endl;
      }
    }
    DynamicAttributesCache::instance().insert(this, attr, this->__attributesHandlers.state());
  }
  return attr;
}

Attributes	Node::dynamicAttributes(std::string name)
{
  std::set<AttributesHandler*>& handlers = this->__attributesHandlers.handlers();
  std::set<AttributesHandler* >::iterator handler;
  Attributes	attrs;

  for (handler = handlers.begin(); handler != handlers.end(); handler++)
  {
    if ((*handler)->name() == name)
    {
      try
      {
        attrs = (*handler)->attributes(this);
      }
      catch (...)
      {
        std::cout << this->absolute() << " attribute handler " << (*handler)->name() << " raise error\n" << std::endl;
      }
      break;
    }
  }
  return attrs;
}

Attributes	                Node::attributes()
{
  Attributes			attr;
  Attributes			dtypes;
  Attributes			nodeAttributes;
  Variant*			vptr;
  std::set<AttributesHandler*>::iterator handler;
  Attributes::iterator it;
  

  dtypes = this->dataType();
  if (!dtypes.empty() && ((vptr = new Variant(dtypes)) != NULL))
    attr["type"] = Variant_p(vptr);
  
  if (this->__fsobj != NULL)
  {
    nodeAttributes = this->fsoAttributes();
    if (!nodeAttributes.empty())
    {
      vptr = new Variant(nodeAttributes);
      if (vptr != NULL)
        attr[this->__fsobj->name] = Variant_p(vptr);
    }
  }

  Attributes    dynAttrs = this->dynamicAttributes();

  attr.insert(dynAttrs.begin(), dynAttrs.end());

  return attr;
}

std::list<std::string>		Node::dynamicAttributesNames(void)
{
  std::set<AttributesHandler*>& handlers = this->__attributesHandlers.handlers();
  std::set<AttributesHandler* >::iterator handler;
  std::list<std::string>	names;

  for (handler = handlers.begin(); handler != handlers.end(); handler++)
    names.push_back((*handler)->name());

  return (names);
}

AttributesHandlers&              Node::attributesHandlers(void)
{
  return (this->__attributesHandlers);
}

bool			        Node::registerAttributes(AttributesHandler* ah)
{
  return (this->__attributesHandlers.add(ah)); 
}


void            Node::attributesByTypeFromVariant(Variant_p rcvar, uint8_t type, Attributes* result, std::string current)
{
  if (rcvar->type() == typeId::List)
    {
      std::list<Variant_p > lvariant = rcvar->value<std::list< Variant_p > >();
      std::list<Variant_p >::iterator it = lvariant.begin();
      for (; it != lvariant.end(); it++)
	this->attributesByTypeFromVariant((*it), type, result, current);
    }
  else if (rcvar->type() == typeId::Map)
    {
      Attributes mvariant = rcvar->value<Attributes >();
      Attributes::iterator it = mvariant.begin();
      std::string	abs;
      for (; it != mvariant.end(); it++)
	{
	  if (current.empty())
	    abs = (*it).first;
	  else
	    abs = current + '.' + (*it).first;
	  if (it->second->type() == type)
	    result->insert(std::pair<std::string, Variant_p >(abs, it->second));
	  else
	    this->attributesByTypeFromVariant(it->second, type, result, abs);
	}
    }
}


void	Node::attributesNamesAndTypesFromVariant(Variant_p rcvar, std::map<std::string, uint8_t> *namestypes, std::string current)
{
  if (rcvar->type() == typeId::List)
    {
      std::list<Variant_p > lvariant = rcvar->value<std::list< Variant_p > >();
      std::list<Variant_p >::iterator it = lvariant.begin();
      for (; it != lvariant.end(); it++)
	this->attributesNamesAndTypesFromVariant((*it), namestypes, current);
    }
  else if (rcvar->type() == typeId::Map)
    {
      Attributes mvariant = rcvar->value<Attributes >();
      Attributes::iterator it = mvariant.begin();
      std::string	abs;
      for (; it != mvariant.end(); it++)
	{
	  if (current.empty())
	    abs = it->first;
	  else
	    abs = current + '.' + it->first;
	  namestypes->insert(std::pair<std::string, uint8_t>(abs, it->second->type()));
	  this->attributesNamesAndTypesFromVariant(it->second, namestypes, abs);
	}
    }  
}

void	Node::attributesNamesFromVariant(Variant_p rcvar, std::list<std::string > *names)
{
  if (rcvar->type() == typeId::List)
    {
      std::list< Variant_p > lvariant = rcvar->value<std::list< Variant_p > >();
      std::list< Variant_p >::iterator it = lvariant.begin();
      for (; it != lvariant.end(); it++)
	this->attributesNamesFromVariant((*it), names); 
    }
  else if (rcvar->type() == typeId::Map)
    {
      Attributes mvariant = rcvar->value< Attributes >();
      Attributes::iterator it = mvariant.begin();
      for (; it != mvariant.end(); it++)
	{
	  names->push_back(it->first);
	  this->attributesNamesFromVariant(it->second, names);
	}
    }
}

void	Node::attributesNamesFromVariant(Variant_p rcvar, std::list<std::string > *names, std::string current)
{
  if (rcvar->type() == typeId::List)
    {
      std::list<Variant_p > lvariant = rcvar->value<std::list< Variant_p > >();
      std::list<Variant_p >::iterator it = lvariant.begin();
      for (; it != lvariant.end(); it++)
	this->attributesNamesFromVariant((*it), names, current);
    }
  else if (rcvar->type() == typeId::Map)
    {
      Attributes mvariant = rcvar->value< Attributes >();
      Attributes::iterator it = mvariant.begin();
      std::string	abs;
      for (; it != mvariant.end(); it++)
	{
	  if (current.empty())
	    abs = it->first;
	  else
	    abs = current + '.' + it->first;
	  names->push_back(abs);
	  this->attributesNamesFromVariant(it->second, names, abs);
	}
    }
}

std::list<std::string>  	Node::attributesNames(attributeNameType tname)
{
  std::list<std::string>	result;
  Attributes			attr;
  Attributes::iterator		attrit;

  attr = this->attributes();
  for (attrit = attr.begin(); attrit != attr.end(); attrit++)
    {
      result.push_back(attrit->first);
      if (tname == ABSOLUTE_ATTR_NAME)
	this->attributesNamesFromVariant(attrit->second, &result, attrit->first);
      else
	this->attributesNamesFromVariant(attrit->second, &result);
    }
  return (result);
}

void		Node::attributesByNameFromVariant(Variant_p rcvar, std::string name, std::list< Variant_p >* result)
{
  if (rcvar->type() == typeId::List)
    {
      std::list< Variant_p > lvariant = rcvar->value<std::list< Variant_p > >();
      std::list< Variant_p >::iterator it;

      for (it = lvariant.begin(); it != lvariant.end(); it++)
	this->attributesByNameFromVariant((*it), name, result);
    }
  else if (rcvar->type() == typeId::Map)
    {
      Attributes mvariant = rcvar->value< Attributes >();
      Attributes::iterator it;

      for (it = mvariant.begin(); it != mvariant.end(); it++)
	{
	  if (it->first == name)
	    result->push_back(it->second);
	  else
	    this->attributesByNameFromVariant(it->second, name, result);
	}
    }
}

void		Node::attributeByAbsoluteNameFromVariant(Variant_p rcvar, std::string name, std::list< Variant_p >* result)
{
  std::string	subname;
  std::string	subabs;
  size_t	idx;

  idx = name.find(".");
  if (idx != std::string::npos)
    {
      subname = name.substr(0, idx);
      subabs = name.substr(idx+1, name.size());
    }
  else
    {
      subname = name;
      subabs = "";
    }
  if ((rcvar->type() == typeId::List) && (!subabs.empty()))
    {
      std::list< Variant_p > lvariant = rcvar->value<std::list< Variant_p > >();
      std::list< Variant_p >::iterator it;

      for (it = lvariant.begin(); it != lvariant.end(); it++)
	if ((*it)->type() == typeId::Map)
	  this->attributeByAbsoluteNameFromVariant((*it), subabs, result);
    }
  else if (rcvar->type() == typeId::Map)
    {
      Attributes mvariant = rcvar->value< Attributes >();
      Attributes::iterator it;
      
      it = mvariant.find(subname);
      if (it != mvariant.end())
	{
	  if (!subabs.empty())
	    this->attributeByAbsoluteNameFromVariant(it->second, subabs, result);
	  else
	    result->push_back(it->second);
	}
    }
}

std::list< Variant_p >		Node::attributesByName(std::string name, attributeNameType tname)
{
  Attributes			attr;
  Attributes::iterator		attrit;
  std::list< Variant_p >	result;

  attr = this->attributes();
  if (tname == ABSOLUTE_ATTR_NAME)
    {
      std::string	subname;
      std::string	subabs;
      size_t		idx;
      
      idx = name.find(".");
      if (idx != std::string::npos)
	{
	  subname = name.substr(0, idx);
	  subabs = name.substr(idx+1, name.size());
	  if ((attrit = attr.find(subname)) != attr.end())
	    this->attributeByAbsoluteNameFromVariant(attrit->second, subabs, &result);
	}
      else if ((attrit = attr.find(name)) != attr.end())
	result.push_back(attrit->second);
    }
  else
    {      
      for (attrit = attr.begin(); attrit != attr.end(); attrit++)
	{
	  if (attrit->first == name)
	    result.push_back(attrit->second);
	  this->attributesByNameFromVariant(attrit->second, name, &result);
	}
    }
  return result;
}

Attributes			Node::attributesByType(uint8_t type)
{
  Attributes			attr;
  Attributes			result;
  Attributes::iterator		attrit;
  
  attr = this->attributes();
  for (attrit = attr.begin(); attrit != attr.end(); attrit++)
    {
      if (attrit->second->type() == type)
	result[attrit->first] = attrit->second;
      this->attributesByTypeFromVariant(attrit->second, type, &result, attrit->first);
    }
  return result;
}


std::map<std::string, uint8_t>	Node::attributesNamesAndTypes()
{
  std::map<std::string, uint8_t>	result;
  Attributes				attr;
  Attributes::iterator			attrit;
  
  attr = this->attributes();
  for (attrit = attr.begin(); attrit != attr.end(); attrit++)
    {
      result.insert(std::pair<std::string, uint8_t>(attrit->first, attrit->second->type()));
      this->attributesNamesAndTypesFromVariant(attrit->second, &result, attrit->first);
    }
  return result;
}

std::list<std::string>		Node::compatibleModules(void)
{
  std::list<std::string>        	result;
  Attributes				dtypes;
  ConfigManager*			cm;
  std::map<std::string, Constant*>	constants;
  std::string				ext;

  if ((cm = ConfigManager::Get()) != NULL)
    {
      constants = cm->constantsByName("mime-type");
      if (!constants.empty())       
      	{
      	  dtypes = this->dataType();
      	  if (!dtypes.empty())
      	    this->__compatibleModulesByType(constants, dtypes, result);
      	}
      ext = this->extension();
      if (!ext.empty())
      	{
      	  constants = cm->constantsByName("extension-type");
      	  if (!constants.empty())
      	    this->__compatibleModulesByExtension(constants, ext, result);
      	}
    }
  return result;
}

bool	                        Node::isCompatibleModule(std::string modname)
{
  
  ConfigManager*		cm;
  Config*			conf;
  Constant*			constant;
  std::list< Variant_p >	values;
  std::list< Variant_p >::iterator	it;
  bool				compat;
  
  compat = false;
  if (((cm = ConfigManager::Get()) != NULL) && ((conf = cm->configByName(modname)) != NULL))
    {
      Attributes	dtypes;
      std::string	ext;

      dtypes = this->dataType();
      ext = this->extension();
      if ((constant = conf->constantByName("mime-type")) != NULL)
	{
	  values = constant->values();
	  for (Attributes::iterator mit = dtypes.begin(); mit != dtypes.end(); mit++)
	    {
	      if (mit->second->type() == typeId::String)
		{
		  std::string	dtype = mit->second->value<std::string>();
		  it = values.begin();
		  while (it != values.end() && !compat)
		    {
		      if ((*it)->type() == typeId::String && dtype.find((*it)->value<std::string>()) != std::string::npos)
			compat = true;
		      it++;
		    }
		}
	    }
	}
      if (!ext.empty() && !compat && ((constant = conf->constantByName("extension-type")) != NULL))
	{
	  values = constant->values();
	  it = values.begin();
	  while (it != values.end() && !compat)
	    {
	      if ((*it)->type() == typeId::String && (*it)->value<std::string>().find(ext) != std::string::npos)
		compat = true;
	      it++;
	    }
	}
    }
  return compat;
}

void		Node::__compatibleModulesByType(const std::map<std::string, Constant*>& cmime, Attributes& dtypes, std::list<std::string>& result)
{
  std::map<std::string, Constant*>::const_iterator	cit;
  std::list<Variant_p >					lvalues;
  std::list<Variant_p >::iterator			lit;
  Attributes::iterator					dit;
  bool							match;

  for (cit = cmime.begin(); cit != cmime.end(); cit++)
    {
      match = false;
      if ((cit->second != NULL) && (cit->second->type() == typeId::String))
  	{
  	  lvalues = cit->second->values();
	  lit = lvalues.begin();
  	  while (lit != lvalues.end() && !match)
  	    {
	      dit = dtypes.begin();
  	      while (dit != dtypes.end() && !match)
  		{
  		  std::string	cval = (*lit)->value<std::string>();
  		  if ((dit->second != NULL) && (dit->second->type() == typeId::String)
  		      && (dit->second->value<std::string>().find(cval) != std::string::npos))
  		    {
  		      match = true;
  		      result.push_back(cit->first);
  		    }
  		  dit++;
  		}
  	      lit++;
  	    }
  	}
    }
}

void		Node::__compatibleModulesByExtension(const std::map<std::string, Constant*>& cextensions, std::string& ext, std::list<std::string>& result)
{
  std::map<std::string, Constant*>::const_iterator	cit;
  std::list< Variant_p >				lvalues;
  std::list< Variant_p >::iterator			lit;

  for (cit = cextensions.begin(); cit != cextensions.end(); cit++)
    {
      if ((cit->second != NULL) && (cit->second->type() == typeId::String))
	{
	  lvalues = cit->second->values();
	  for (lit = lvalues.begin(); lit != lvalues.end(); lit++)
	    if (ext == (*lit)->value<std::string>())
	      result.push_back(cit->first);
	}
    }
}

bool    	Node::setTag(std::string name)
{
  Tag_p t =  TagsManager::get().tag(name);

  if (t != NULL) 	
  {
    this->__tags |= ((uint64_t) 1) << t->id();
    return true;
  }
  return false;
}

bool 	        Node::setTag(uint32_t id)
{
  if (id != 0 && (TagsManager::get().tag(id) != NULL))
  {
    this->__tags |= ((uint64_t) 1) << id;
    return true;
  }
  return false;
}

bool	         Node::removeTag(std::string name)
{
  Tag_p  t =  TagsManager::get().tag(name);

  if (t != NULL) 	
    return (this->removeTag(t->id()));
  return false;
}

bool	        Node::removeTag(uint32_t id)
{
  if ((this->__tags & (((uint64_t) 1) << id))  == (((uint64_t) 1) << id))
  {
    this->__tags ^= ((uint64_t) 1) << id;
    return true;
  }
  return false;
}

bool            Node::isTagged(uint32_t id)
{
  if ((this->__tags & (((uint64_t) 1) << id))  == (((uint64_t) 1) << id))
    return true;
  return false;
}

bool            Node::isTagged(std::string name)
{
  Tag_p  t = TagsManager::get().tag(name);

  if (t->id() != 0)
    return (this->isTagged(t->id()));
  return false;
}

std::vector<Tag_p > 	Node::tags()
{
  uint8_t 		i    = 1;
  TagsManager&		tm   = TagsManager::get();
  std::vector<Tag_p > 	tags;

  for (; i < 64; i++)
     if (this->isTagged(i))
     {
        try 
        {
          Tag_p t = tm.tag(i);
          if (t != NULL)
            tags.push_back(t);
        }
        catch (envError)
        {
        }
     }

  return (tags);
}

std::vector<uint32_t>	Node::tagsId()
{
  uint32_t  		i = 1;
  std::vector<uint32_t> tags;

  for (; i < 64; i++)
     if (this->isTagged(i))
       tags.push_back(i);
      
  return (tags);
}


/*
 *  Attributes Handler
*/

AttributesHandler::AttributesHandler(std::string handlerName)
{
  this->__handlerName = handlerName;
}

std::string AttributesHandler::name(void)
{
  return (this->__handlerName);
}

AttributesHandler::~AttributesHandler()
{
}

/*
 * Attributes Handlers
 */


AttributesHandlers::AttributesHandlers()
{
  this->__state = 0;
}

AttributesHandlers::~AttributesHandlers()
{
}

size_t AttributesHandlers::count()
{
  return this->__handlers.size();
}

std::set<AttributesHandler* >& AttributesHandlers::handlers()
{
  return this->__handlers;
}

void    AttributesHandlers::updateState(void)
{
  this->__state++;
}

const uint64_t AttributesHandlers::state(void)
{
  return (this->__state);
}       

bool AttributesHandlers::add(AttributesHandler* ah)
{
  return this->__handlers.insert(ah).second;
}

bool AttributesHandlers::remove(AttributesHandler* attributeHandler)
{
  this->__handlers.erase(attributeHandler);

  return true;
}

bool AttributesHandlers::remove(std::string handlerName)
{
  std::set<AttributesHandler*>::iterator handler;
  
  for (handler = this->__handlers.begin(); handler != this->__handlers.end(); handler++)
  {
     if (handlerName == (*handler)->name())
     {
       this->__handlers.erase(handler);
       return true;
     }
  }

  return false;
}
