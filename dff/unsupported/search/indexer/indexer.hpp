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
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

#ifndef __INDEXER_H_
# define __INDEXER_H_
 
#include "vfs.hpp"
#include "argument.hpp"
#include "mfso.hpp"
#include "index.hpp"
 
class   Indexer : public mfso
{
public:
  Indexer();                                 
  ~Indexer();
  virtual void          start(std::map<std::string, Variant *>arg);

private:
  Node *	__node;
  Index *	__index;
  
private:
  void		__recurseNode(Node * node);

};
 
#endif /* __INDEXER_H_ */
