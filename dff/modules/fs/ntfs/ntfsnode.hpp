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

#ifndef __NTFSNODE_HPP__
#define __NTFSNODE_HPP__

#include "ntfs.hpp"
#include "node.hpp"
#include "vfile.hpp"
#include "mftentry.hpp"
#include "attributes/data.hpp"
#include "attributes/filename.hpp"
#include "boot.hpp"

class NtfsNode : public Node
{
public:

  NtfsNode(std::string, uint64_t, Node *, class Ntfs *, bool, AttributeFileName *,
	   AttributeStandardInformation *, MftEntry *);
  NtfsNode(std::string, uint64_t, Node *, Ntfs *, bool, AttributeFileName *,
	   AttributeStandardInformation *, MftEntry *, uint32_t, uint64_t);
  NtfsNode(std::string Name, uint64_t size, Node *parent, Ntfs *fsobj,
	   BootBlock *bootBlock);
  ~NtfsNode();
  virtual void			fileMapping(FileMapping *);
  void				node(Node *node) { _node = node; };
  void				contentOffset(uint64_t offset) { _contentOffset = offset; };
  void				data(AttributeData *data) { _data = data; };
  uint32_t			getMftEntry() { return _mftEntry; };
  void				dataOffsets(std::list<uint64_t> d) { _dataOffsets = d; };
  Attributes			_attributes(void);

private:
  bool						_isFile;
  AttributeStandardInformation			*_SI;
  uint32_t					_mftEntry;
  uint64_t					_physOffset;
  MftEntry					*_mft;
  BootBlock					*_bootBlock;

  std::map<std::string, Variant_p >		_headerToAttribute(Attribute *);
  void						_standardInformation(std::map<std::string, Variant_p > *, AttributeStandardInformation *);
  void						_fileName(std::map<std::string, Variant_p > *, AttributeFileName *);
  void						_dataAttribute(std::map<std::string, Variant_p > *, AttributeData *);
  void						_setNextAttrData(FileMapping *fm, uint64_t totalOffset);

  FileMapping		*_fm;
  Node			*_node;
  AttributeData		*_data;
  uint64_t		_contentOffset;
  std::list<uint64_t>	_dataOffsets;

  void		_offsetResident(FileMapping *);
  void		_offsetFromRunList(FileMapping *);
  
  AttributeFileName	*_metaFileName;
};

#endif
