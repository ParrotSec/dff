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

#ifndef __MFTFILE_HPP__
#define __MFTFILE_HPP__

#include "vfs.hpp"
#include "common.hpp"
#include "attribute.hpp"

#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif


#include "attributes/standardinformation.hpp"
#include "attributes/filename.hpp"
#include "attributes/securitydescriptor.hpp"
#include "attributes/indexroot.hpp"
#include "attributes/indexallocation.hpp"
#include "attributes/data.hpp"
#include "attributes/bitmap.hpp"
#include "mftentry.hpp"

class MftFile {
public:
  MftFile(VFile *, uint16_t, uint16_t, uint16_t, uint16_t);
  ~MftFile();
  uint16_t		getOffsetListSize();
  uint32_t		getNumberOfRecords();
  uint64_t		getAllocatedSize();
  // Attributes setters
  void			data(Attribute *);
  void			bitmap(Attribute *);
  void			standardInformation(Attribute *);
  void			fileName(Attribute *);
  AttributeFileName	*fileName() { return _fileName; };
  void			securityDescriptor(Attribute *);
  void			indexRoot(Attribute *);
  void			indexAllocation(Attribute *);
  // Attributes getters
  AttributeData			*data() { return _data; };
  AttributeBitmap		*bitmap() { return _bitmap; };
  AttributeIndexRoot		*indexRoot() { return _indexRoot; };
  AttributeIndexAllocation	*indexAllocation() { return _indexAllocation; };

  void			entryDiscovered(uint32_t);
  bool			isEntryDiscovered(uint32_t);
  void			dumpDiscoveredEntries();
  uint32_t		discoverPercent();
  std::map<uint32_t, bool>	getEntryMap() { return _discoveredEntries; };

  MftEntry	*get(uint64_t);

private:
  VFile				*_vfile;
  uint64_t			_currentOffset;
  uint16_t			_offsetListSize;
  uint32_t			_numberOfRecords;

  AttributeStandardInformation	*_standardInformation;
  AttributeFileName		*_fileName;
  AttributeSecurityDescriptor	*_securityDescriptor;
  AttributeIndexRoot		*_indexRoot;
  AttributeIndexAllocation	*_indexAllocation;
  AttributeData			*_data;
  AttributeBitmap		*_bitmap;

  uint16_t	_mftEntrySize;
  uint16_t	_indexRecordSize;
  uint16_t	_sectorSize;
  uint16_t	_clusterSize;
  uint64_t	_allocatedSize;

  std::map<uint32_t, bool>	_discoveredEntries;
};

#endif
