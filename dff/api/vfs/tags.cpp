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

#include "vfs.hpp"
#include "node.hpp"
#include "tags.hpp"

Color::Color()
{
  r = g = b = 0;
}

Color::Color(uint8_t cr, uint8_t cg, uint8_t cb)
{
  this->r = cr;
  this->g = cg;
  this->b = cb;
}

Tag::Tag()
{
}

Tag::Tag(uint32_t id, std::string name, Color color)
{
   this->__id = id;
   this->__name = name;
   this->__color = color;
}

Tag::Tag(uint32_t id, std::string name, uint8_t r, uint8_t g, uint8_t b)
{
  this->__id = id;
  this->__name = name;
  this->__color.r = r;
  this->__color.g = g;
  this->__color.b = b;
}

Tag::~Tag()
{
}

std::string Tag::name(void)
{
  return this->__name;
}

Color    Tag::color(void)
{
  return this->__color;
}

uint32_t Tag::id(void)
{
  return this->__id;
}

void	Tag::setColor(Color color)
{
   this->__color = color;
}

void    Tag::setColor(uint8_t r, uint8_t g, uint8_t b)
{
  this->__color.r = r;
  this->__color.g = g;
  this->__color.b = b;
}

void	Tag::setName(std::string name)
{
  this->__name = name;
}

#define DEFAULT_TAG(n, r, g, b) this->add(std::string(n), r, g, b);

TagsManager::TagsManager()
{
  DEFAULT_TAG("known good",   0, 255,   0)
  DEFAULT_TAG("known bad",    0,   0, 255)
  DEFAULT_TAG("malware",    255,   0,   0)
  DEFAULT_TAG("viewed",     255, 255,   0)
  this->__defaults = this->__tagsList.size();
}

TagsManager&	TagsManager::get()
{
   static TagsManager single;
   return single;
}

uint32_t        TagsManager::add(std::string name, Color color)
{
  return (this->add(name, color.r, color.g, color.b));
}

uint32_t 	TagsManager::add(std::string name, uint8_t r, uint8_t g, uint8_t b)
{
  try 
  {
    Tag_p t  =  this->tag(name);
    return (t->id());
  }
  catch (envError) 
  {
  }

  if (this->__tagsList.size() < 63)
  {
     uint32_t id = this->__tagsList.size() + 1;
 
     Tag_p tag(new Tag(id, name, r, g, b)); 
     this->__tagsList.push_back(tag);
     return (id);
  }
  else
  {
     uint32_t	id = 0;

     for (; id < 63; id++)
     {
        if (this->__tagsList[id] == NULL)
	{
	  this->__tagsList[id] = Tag_p(new Tag(id + 1, name, r, g, b));
	  return (id + 1);
	}
     }
  }

  return (0);
}

uint32_t 	TagsManager::add(std::string name)
{
//getcolorauto XXX //random ??
  return (this->add(name, 100, 170, 80));
}


void            TagsManager::__removeNodesTag(uint32_t id, Node* node)
{
  node->removeTag(id);
  if (!(node->hasChildren()))
    return ;

  std::vector<Node*>           childs = node->children();
  std::vector<Node*>::iterator it = childs.begin();
  for (; it != childs.end(); it++)
     if ((*it) != NULL)
        this->__removeNodesTag(id, (*it));
}

void            TagsManager::__removeNodesTag(uint32_t id)
{
  Node* root = VFS::Get().GetNode("/");

  this->__removeNodesTag(id, root);
}

bool		TagsManager::remove(uint32_t id)
{
    try
    {
      Tag_p t = this->__tagsList.at(id - 1);
      if (t != NULL)
      {
        this->__removeNodesTag(id);
        if (id > this->__defaults)
        {
          this->__tagsList[id - 1] = NULL;
          //delete t; 
          //t = NULL;// hum ca delete vraiment ou vue que c a null ca delte pas et du coup ca reste en rammmmm et ca segfault pas ds le removescript XXX
          return true;
        }
        else
          return false;
      }
    }
    catch (std::exception)
    {
      return false;
    }
    return false;
}


bool		TagsManager::remove(std::string name)
{
  std::vector<Tag_p >::iterator it = this->__tagsList.begin();
  
  for (; it != this->__tagsList.end(); it++)
  {
     if (((*it) != NULL) && ((*it)->name() == name))
       return (this->remove((*it)->id())); 
  } 
  return false;
}

std::vector<Tag_p >*	TagsManager::tags(void)
{
  std::vector<Tag_p >*         tagsList  = new std::vector<Tag_p >;
  std::vector<Tag_p >::iterator it       =  this->__tagsList.begin();

  for (; it != this->__tagsList.end(); it++)
  {
     if ((*it) != NULL)
       tagsList->push_back(Tag_p(*it));
  }

  return (tagsList);
}

Tag_p			TagsManager::tag(uint32_t id)
{
  try 
  {
     Tag_p t = this->__tagsList.at(id - 1);
     if (t != NULL)
       return t;
  }
  catch (std::exception)
  {
  }
  throw envError("Tag not found"); 
}

Tag_p			TagsManager::tag(std::string name)
{
  std::vector<Tag_p >::iterator	it = this->__tagsList.begin();

  for (; it != this->__tagsList.end(); it++)
     if (((*it) != NULL) && (*it)->name() == name)
       return (*it); 

  throw envError("Tag not found");
}
