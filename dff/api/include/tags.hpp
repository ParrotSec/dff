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

#ifndef __TAGS_HPP__
#define __TAGS_HPP__

#ifndef WIN32
  #include <stdint.h>
#elif _MSC_VER >= 1600
  #include <stdint.h>
#else
  #include "wstdint.h"
#endif

#include <string>
#include <vector>
#include "export.hpp"
#include "rc.hpp"

#define Tag_p				RCPtr< Tag >

class Node;

class Color
{
public:
	EXPORT                                        Color();
	EXPORT                                        Color(uint8_t r, uint8_t g, uint8_t b);
	uint8_t                               r;
	uint8_t                               g;
	uint8_t                               b;
};

class Tag : public RCObj
{
private:
  uint32_t				__id;
  std::string				__name;
  Color 				__color;
public:
  EXPORT				~Tag();
  EXPORT                                Tag();
  EXPORT				Tag(uint32_t id, std::string, Color color);
  EXPORT				Tag(uint32_t id, std::string, uint8_t r, uint8_t g, uint8_t b);
  EXPORT uint32_t			id(void);
  EXPORT std::string			name(void);
  EXPORT Color  			color(void);
  EXPORT void				setColor(Color color);
  EXPORT void				setColor(uint8_t r, uint8_t g, uint8_t b);
  EXPORT void				setName(std::string name);
};

class TagsManager 
{
private:
					TagsManager(const TagsManager&);
  EXPORT				TagsManager();
  TagsManager*				operator=(TagsManager&);
  void                                  __removeNodesTag(uint32_t id);
  void                                  __removeNodesTag(uint32_t id, class Node* node);
  std::vector<Tag_p >			__tagsList;
  uint32_t                              __defaults;

public:
  EXPORT static	TagsManager&		get(void);
  EXPORT Tag_p				tag(uint32_t id);
  EXPORT Tag_p				tag(std::string name);
  EXPORT std::vector<Tag_p >*	 	tags(void);	
  EXPORT uint32_t			add(std::string name);
  EXPORT uint32_t			add(std::string name, Color color);
  EXPORT uint32_t			add(std::string name, uint8_t r, uint8_t g, uint8_t b);
  EXPORT bool				remove(uint32_t id);
  EXPORT bool				remove(std::string name);
};

#endif
