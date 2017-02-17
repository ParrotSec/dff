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
 */

#ifndef __FAT_HPP__
#define __FAT_HPP__

#include "node.hpp"
#include "vfile.hpp"
#include "bootsector.hpp"
#include "fatfs.hpp"

#define FATFS_12_MASK   0x00000fff
#define FATFS_16_MASK   0x0000ffff
#define FATFS_32_MASK   0x0fffffff

class FileAllocationTable;

class FileAllocationTableNode: public Node
{
private:
  FileAllocationTable*	__fat;
  uint8_t		__fatnum;
public:
  FileAllocationTableNode(std::string name, uint64_t size, Node* parent, class Fatfs* fatfs);
  ~FileAllocationTableNode();
  void				setContext(FileAllocationTable* fat, uint8_t fatnum);
  virtual void			fileMapping(FileMapping* fm);
  virtual Attributes		_attributes(void);
  virtual Attributes		dataType();
};

class FileAllocationTable
{
private:
  VFile*			vfile;
  Node*				origin;
  class Fatfs*			fatfs;
  class BootSector*		bs;
  void*				__fat;
  std::map<uint32_t, uint32_t>	__freeClustCount;
  std::map<uint32_t, uint32_t>	__allocClustCount;
  std::map<uint32_t, uint32_t>	__badClustCount;
  void				__processClustersStatus();
  bool				__isBadCluster(uint32_t clust);
public:
  FileAllocationTable();
  ~FileAllocationTable();
  void			setContext(Node* origin, class Fatfs* fatfs);

  uint32_t		ioCluster12(uint32_t current, uint8_t which);
  uint32_t		ioCluster16(uint32_t current, uint8_t which);
  uint32_t		ioCluster32(uint32_t current, uint8_t which);
  uint32_t		cluster12(uint32_t current, uint8_t which);
  uint32_t		cluster16(uint32_t current, uint8_t which);
  uint32_t		cluster32(uint32_t current, uint8_t which);


  uint32_t		clusterEntry(uint32_t current, uint8_t which=0);

  uint64_t		clusterOffsetInFat(uint64_t cluster, uint8_t which);

  std::vector<uint64_t>	clusterChainOffsets(uint32_t cluster, uint8_t which=0);
  std::vector<uint32_t>	clusterChain(uint32_t start, uint8_t which=0);

  bool			isFreeCluster(uint32_t cluster);
  bool			isBadCluster(uint32_t cluster);
  bool			clusterEntryIsFree(uint32_t cluster, uint8_t which);
  bool			clusterEntryIsBad(uint32_t cluster, uint8_t which);

  std::vector<uint64_t>	listFreeClustersOffset(uint8_t which=0);
  std::vector<uint32_t>	listFreeClusters(uint8_t which=0);
  uint32_t		freeClustersCount(uint8_t which=0);

  std::list<uint32_t>	listAllocatedClusters(uint8_t which=0);
  uint32_t		allocatedClustersCount(uint8_t which=0);

  std::vector<uint32_t>	listBadClusters(uint8_t which=0);
  uint32_t		badClustersCount(uint8_t which=0);

  uint64_t		clusterToOffset(uint32_t cluster);
  uint32_t		offsetToCluster(uint64_t offset);

  void			diffFats();

  void			makeNodes(Node* parent);
  void			fileMapping(FileMapping* fm, uint8_t which);
  Attributes		attributes(uint8_t which);
};

#endif
