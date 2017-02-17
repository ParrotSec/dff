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

#ifndef __NTFS_HPP__
#define __NTFS_HPP__

//#include "vfile.hpp"
//#include "type.hpp"
//#include "vfs.hpp"
//#include "conf.hpp"

#include <map>
#include "common.hpp"
#include "boot.hpp"
#include "mftentry.hpp"
#include "attribute.hpp"
#include "ntfsnode.hpp"
#include "mftfile.hpp"
#include "vlink.hpp"

#include "mfso.hpp"

#if defined(__linux__)
 #include <bits/wordsize.h>
#elif defined(__FreeBSD__)
 #include <machine/elf.h>
 #define __WORDSIZE	__ELF_WORD_SIZE
#elif defined(WIN64) || defined(WIN32)
 #if defined(WIN64)
  #define __WORDSIZE	64
 #else
  #define __WORDSIZE	32
 #endif
#endif

#define NTFS_ROOT_DIR_MFTENTRY	0x5
#if __WORDSIZE == 64
#define NTFS_ROOT_DIR_PARENTREF	0x0005000000000005UL
#else
#define NTFS_ROOT_DIR_PARENTREF	0x0005000000000005ULL
#endif

class Ntfs : public mfso
{
public:
  Ntfs();
  ~Ntfs();
  virtual void		start(std::map<std::string, Variant_p >);
  dff::Mutex		_mutex;
private:
  Node		*_node;
  uint64_t	_mftDecode;
  uint64_t	_indexDecode;
  class NtfsNode	*_root;
  class NtfsNode	*_unallocRootNode;
  NtfsNode	*_orphan;
  VFile		*_vfile;
  Boot		*_boot;
  MftEntry	*_mftEntry;	// one MFT entry
  MftFile	*_mft;		// MFT file
  MftFile	*_mftMainFile;
  uint64_t	_rootOffset;	// offset of mftEntry corresponding to root of filesystem
  MftFile	*_rootDirectory;
  std::string	_currentState;

  std::map<uint32_t, std::vector<Node *> >	_mftEntryToNode;

  void		_setStateInfo(std::string);
  void		_setStateInfo(uint32_t);
  void		_setMftMainFile(uint64_t);
  void		_setRootDirectory(uint64_t);
  void		_walkMftMainFile();
  void		_rootSearch();
  void		_deletedNodeWithADS(uint64_t, uint32_t, uint32_t,
				    AttributeStandardInformation *);
  void		_createOrphanOrDeleted(std::string,
				       AttributeFileName *, bool,
				       AttributeData *, uint32_t,
				       AttributeStandardInformation *,
				       uint64_t);
  void		_createDeletedWithParent(std::string,
					 std::list<uint64_t>, uint32_t,
					 AttributeFileName *,
					 AttributeData *, bool,
					 AttributeStandardInformation *,
					 uint64_t);
  NtfsNode	*_ntfsNodeExists(std::string, NtfsNode *);
  uint32_t	_searchIndexesInEntry(uint64_t, AttributeIndexRoot **,
				      AttributeIndexAllocation **);
  void		_initTreeWalk(AttributeIndexRoot *, AttributeIndexAllocation *,
			      uint32_t, uint32_t *, uint32_t *);
  void		_updateTreeWalk(AttributeIndexRoot *,
				AttributeIndexAllocation *, uint32_t *,
				uint32_t *, bool *);
  NtfsNode	*_createRegularADSNodes(uint64_t, uint32_t, uint32_t,
					AttributeStandardInformation *, Node *,
				       AttributeFileName *);
  void		_createRegularNode(Node *, uint32_t, uint64_t, uint32_t);
  void		_createLinkedNode(Node *, uint32_t, uint32_t);
  void		_parseDirTree(Node *, uint32_t, uint64_t);
  void		_checkOrphanEntries();
  void		_readBitmap();
};

#endif
