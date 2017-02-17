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

#ifndef __DOS_HPP__
#define __DOS_HPP__

#include "exceptions.hpp"
#include "vfile.hpp"
#include "node.hpp"
#include "partition.hpp"

#include <vector>
#include <deque>

#define IS_EXTENDED(t) ((((t) == 0x05) || ((t) == 0x0F) || ((t) == 0x85)) ? 1 : 0)

typedef struct		
{
  uint8_t		status;//0x80 = bootable, 0x00 = non-bootable, other = invalid
  uint8_t		start_head;
  uint8_t	        start_sector; //sector in bit 5-0, bits 9-8 of cylinders are in bits 7-6...
  uint8_t		start_cylinder; // bits 7-0
  uint8_t		type;
  uint8_t		end_head;
  uint8_t		end_sector; //sector in bit 5-0, bits 9-8 of cylinders are in bits 7-6...
  uint8_t		end_cylinder; //bits 7-0
  uint32_t		lba;
  uint32_t		total_blocks;
}		        dos_pte;


// typedef struct
// {
//   uint32_t	start;
//   uint32_t	end;
//   uint32_t	meta;
// }		entry;

/*
"code" field is usually empty in extended boot record but could contain
another boot loader or something volontary hidden...  
this field could also contain IBM Boot Manager starting at 0x18A.

Normally, there are only two partition entries in extended boot records
followed by 32 bytes of NULL bytes. It could be used to hide data or even
2 other partition entries.
*/
typedef struct
{
  uint8_t	code[440];
  union
  {
    struct
    {
      uint8_t	disk_signature[4];
      uint8_t	padding[2];
    }mbr;
    struct
    {
      uint8_t	code[6];
    }ebr;
  } a;
  uint8_t	partitions[64];
  short		signature; //0xAA55
}		dos_partition_record;

typedef struct
{
  dos_pte*	pte;
  uint64_t	entry_offset;
  uint8_t	type;
  uint32_t	slot;
  uint32_t	sslot;
}		metadatum;

class DosPartition;

class DosPartitionNode: public Node
{
private:
  uint64_t		__entry;
  uint8_t		__type;
  DosPartition*		__handler;
public:
  DosPartitionNode(std::string name, uint64_t size, Node* parent, class Partition* fsobj);
  ~DosPartitionNode();
  void			setCtx(DosPartition* handler, uint64_t entry, uint8_t type);
  virtual void		fileMapping(FileMapping* fm);
  virtual Attributes	_attributes(void);
  virtual Attributes	dataType();
  virtual std::string	icon();
};

#define PRIMARY		0x01
#define EXTENDED	0x02
#define	LOGICAL		0x04
#define HIDDEN		0x08
#define UNALLOCATED	0x10

typedef std::map<uint64_t, metadatum* >	metamap;
typedef metamap::iterator		metaiterator;

class DosPartition
{
private:
  uint32_t				__logical;
  uint32_t				__primary;
  uint32_t				__extended;
  uint32_t				__hidden;
  uint32_t				__slot;
  std::map<uint64_t, metadatum*>	allocated;
  std::map<uint64_t, metadatum*>	unallocated;
  Node*					root;
  Node*					origin;
  class Partition*			fsobj;
  VFile*				vfile;
  uint32_t				sectsize;
  uint64_t				offset;
  bool					mbrBadMagic;
  uint64_t				ebr_base;
  std::map<std::string, Variant_p >	res;
  dos_pte*				toPte(uint8_t* buff);
  void					makeNodes();
  void					makeUnallocated();
  void					makeResults();
  Attributes				__entryAttributes(metaiterator mit);
public:
  DosPartition();
  ~DosPartition();
  Attributes		result();
  Attributes		entryAttributes(uint64_t entry, uint8_t type);
  void			mapping(FileMapping* fm, uint64_t entry, uint8_t type);
  void			open(Node* origin, uint64_t offset, uint32_t sectsize, Partition* fsobj) throw (vfsError);
  void			readEbr(uint64_t cur, uint64_t shift=0) throw (vfsError);
  void			readMbr() throw (vfsError);
};

#endif
