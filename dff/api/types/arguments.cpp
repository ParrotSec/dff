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
 *  Frederic B. <fba@digital-forensic.org>
 */


#include "arguments.hpp"

Arguments::Arguments(std::string origin)
{
  this->__origin = origin;
}

Arguments::~Arguments()
{
}

bool					Arguments::add(std::string name, Variant* value)
{
}

Variant*				Arguments::valueFromKey(std::string name)
{
}

std::map<std::string, Variant*>		Arguments::items()
{
}

std::list<std::string>			Arguments::keys()
{
}

std::list<Variant*>			Arguments::values()
{
}
