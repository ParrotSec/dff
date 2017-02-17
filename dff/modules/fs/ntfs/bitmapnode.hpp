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

#ifndef __BITMAPNODE_HPP__
#define __BITMAPNODE_HPP__

#include "ntfs.hpp"
#include "node.hpp"
#include "vfile.hpp"
#include "mftentry.hpp"

class BitmapNode : public Node
{
public:

  BitmapNode(std::string, uint64_t, Node *, Node *, Ntfs *, uint64_t, uint16_t);
  ~BitmapNode();
  virtual void			fileMapping(FileMapping *);
  Attributes			_attributes(void);

  void				contentOffset(uint64_t offset) { _contentOffset = offset; };
  void				data(AttributeData *data) { _data = data; };
  uint32_t			getMftEntry() { return _mftEntry; };
  void				dataOffsets(std::list<uint64_t> d) { _dataOffsets = d; };
private:
  bool						_isFile;

  uint32_t					_mftEntry;
  uint64_t					_physOffset;
  MftEntry					*_mft;

  uint16_t		_clusterSize;
  uint64_t		_startingCluster;

  FileMapping		*_fm;
  Node			*_node;
  AttributeData		*_data;
  uint64_t		_contentOffset;
  std::list<uint64_t>	_dataOffsets;

  AttributeFileName	*_metaFileName;
};

#endif
