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

#include "dos.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>

char partition_types[256][128] = 
{
  "Empty",
  "DOS 12-bit FAT",
  "XENIX root",
  "XENIX /usr",
  "DOS 3.0+ 16-bit FAT (up to 32M)",
  "DOS 3.3+ Extended Partition",
  "DOS 3.31+ 16-bit FAT (over 32M)",
  "QNX2.x pre-1988",
  "QNX 1.x and 2.x (qny)",
  "QNX 1.x and 2.x (qnz)",
  "OPUS",
  "WIN95 OSR2 FAT32",
  "WIN95 OSR2 FAT32, LBA-mapped",
  "Unknown",
  "WIN95: DOS 16-bit FAT, LBA-mapped",
  "WIN95: Extended partition, LBA-mapped",
  "OPUS (?)",
  "Hidden DOS 12-bit FAT",
  "Configuration/diagnostics partition",
  "Unknown",
  "Hidden DOS 16-bit FAT &lt;32M",
  "Unknown",
  "Hidden DOS 16-bit FAT &gt;=32M",
  "Hidden IFS (e.g., HPFS)",
  "AST SmartSleep Partition",
  "Unused",
  "Unknown",
  "Hidden WIN95 OSR2 FAT32",
  "Hidden WIN95 OSR2 FAT32, LBA-mapped",
  "Unknown",
  "Hidden WIN95 16-bit FAT, LBA-mapped",
  "Unknown",
  "Unused",
  "Unused",
  "Unused",
  "Reserved",
  "NEC DOS 3.x",
  "Unknown",
  "Reserved",
  "RouterBOOT kernel partition",
  "Unknown",
  "Unknown",
  "AtheOS File System (AFS)",
  "SyllableSecure (SylStor)",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unknown",
  "Reserved",
  "NOS",
  "Reserved",
  "Reserved",
  "JFS on OS/2 or eCS",
  "Reserved",
  "Unknown",
  "THEOS ver 3.2 2gb partition",
  "THEOS ver 4 spanned partition",
  "THEOS ver 4 4gb partition",
  "THEOS ver 4 extended partition",
  "PartitionMagic recovery partition",
  "Hidden NetWare",
  "Unknown",
  "Unknown",
  "PICK",
  "PPC PReP (Power PC Reference Platform) Boot",
  "Windows 2000 dynamic extended partition marker",
  "Linux native (sharing disk with DRDOS)",
  "GoBack partition",
  "EUMEL/Elan",
  "EUMEL/Elan",
  "EUMEL/Elan",
  "EUMEL/Elan",
  "Unknown",
  "AdaOS Aquila (Withdrawn)",
  "Unknown",
  "Oberon partition",
  "QNX4.x",
  "QNX4.x 2nd part",
  "Oberon partition",
  "Native Oberon (alt)",
  "Novell",
  "Microport SysV/AT",
  "Disk Manager 6.0 Aux3",
  "Disk Manager 6.0 Dynamic Drive Overlay (DDO)",
  "EZ-Drive",
  "DM converted to EZ-BIOS",
  "VNDI Partition",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unknown",
  "Priam EDisk",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unknown",
  "SpeedStor",
  "Unknown",
  "Unix System V (SCO, ISC Unix, UnixWare, ...), Mach, GNU Hurd",
  "Novell Netware 286, 2.xx",
  "Novell Netware 386, 3.xx or 4.xx",
  "Novell Netware SMS Partition",
  "Novell",
  "Novell",
  "Novell Netware 5+, Novell Netware NSS Partition",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unknown",
  "??",
  "Unknown",
  "DiskSecure Multi-Boot",
  "Reserved",
  "V7/x86",
  "Reserved",
  "Scramdisk partition",
  "IBM PC/IX",
  "Reserved",
  "VNDI Partition",
  "XOSL FS",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unused",
  "Unused",
  "MINIX until 1.4a",
  "Mitac disk manager",
  "Linux swap",
  "Linux native partition",
  "Hibernation partition",
  "Linux extended partition",
  "FAT16 volume set",
  "NTFS volume set",
  "Linux plaintext partition table",
  "Unknown",
  "Linux Kernel Partition (used by AiR-BOOT)",
  "Legacy Fault Tolerant FAT32 volume",
  "Legacy Fault Tolerant FAT32 volume using BIOS extd INT 13h",
  "Free FDISK 0.96+ hidden Primary DOS FAT12 partitition",
  "Linux Logical Volume Manager partition",
  "Unknown",
  "Free FDISK 0.96+ hidden Primary DOS FAT16 partitition",
  "Free FDISK 0.96+ hidden DOS extended partitition",
  "Free FDISK 0.96+ hidden Primary DOS large FAT16 partitition",
  "Amoeba",
  "Amoeba bad block table",
  "MIT EXOPC native partitions",
  "CHRP ISO-9660 filesystem",
  "Free FDISK 0.96+ hidden Primary DOS FAT32 partitition",
  "Datalight ROM-DOS Super-Boot Partition",
  "DCE376 logical drive",
  "Free FDISK 0.96+ hidden Primary DOS FAT16 partitition (LBA)",
  "Free FDISK 0.96+ hidden DOS extended partitition (LBA)",
  "Unknown",
  "Unknown",
  "ForthOS partition",
  "BSD/OS",
  "Laptop hibernation partition",
  "HP Volume Expansion (SpeedStor variant)",
  "Unknown",
  "HP Volume Expansion (SpeedStor variant)",
  "HP Volume Expansion (SpeedStor variant)",
  "BSD/386, 386BSD, NetBSD, FreeBSD",
  "HP Volume Expansion (SpeedStor variant)",
  "NeXTStep",
  "Mac OS-X",
  "NetBSD",
  "Olivetti Fat 12 1.44MB Service Partition",
  "GO! partition",
  "Unknown",
  "Unknown",
  "ShagOS filesystem",
  "MacOS X HFS",
  "BootStar Dummy",
  "QNX Neutrino Power-Safe filesystem",
  "QNX Neutrino Power-Safe filesystem",
  "QNX Neutrino Power-Safe filesystem",
  "HP Volume Expansion (SpeedStor variant)",
  "Unknown",
  "Corrupted Windows NT mirror set (master), FAT16 file system",
  "BSDI BSD/386 filesystem",
  "BSDI BSD/386 swap partition",
  "Unknown",
  "Unknown",
  "Boot Wizard hidden",
  "Acronis backup partition",
  "Unknown",
  "Solaris 8 boot partition",
  "New Solaris x86 partition",
  "DR-DOS/Novell DOS secured partition",
  "DRDOS/secured (FAT-12)",
  "Hidden Linux",
  "Hidden Linux swap",
  "DRDOS/secured (FAT-16, &lt; 32M)",
  "DRDOS/secured (extended)",
  "Windows NT corrupted FAT16 volume/stripe set",
  "Syrinx boot",
  "Reserved for DR-DOS 8.0+",
  "Reserved for DR-DOS 8.0+",
  "Reserved for DR-DOS 8.0+",
  "DR-DOS 7.04+ secured FAT32 (CHS)/",
  "DR-DOS 7.04+ secured FAT32 (LBA)/",
  "CTOS Memdump?",
  "DR-DOS 7.04+ FAT16X (LBA)/",
  "DR-DOS 7.04+ secured EXT DOS (LBA)/",
  "Multiuser DOS secured partition",
  "Old Multiuser DOS secured FAT12",
  "Unknown",
  "Unknown",
  "Old Multiuser DOS secured FAT16 &lt;32M",
  "Old Multiuser DOS secured extended partition",
  "Old Multiuser DOS secured FAT16 &gt;=32M",
  "Unknown",
  "CP/M-86",
  "Unknown",
  "Powercopy Backup",
  "KDG Telemetry SCPU boot",
  "Unknown",
  "Hidden CTOS Memdump?",
  "Dell PowerEdge Server utilities (FAT fs)",
  "BootIt EMBRM",
  "Unknown",
  "DOS access or SpeedStor 12-bit FAT extended partition",
  "Unknown",
  "DOS R/O or SpeedStor",
  "SpeedStor 16-bit FAT extended partition &lt; 1024 cyl.",
  "Unknown",
  "Storage Dimensions SpeedStor",
  "Unknown",
  "LUKS",
  "Unknown",
  "Unknown",
  "BeOS BFS",
  "SkyOS SkyFS",
  "Unused",
  "Indication that this legacy MBR is followed by an EFI header",
  "Partition that contains an EFI file system",
  "Linux/PA-RISC boot loader",
  "Storage Dimensions SpeedStor",
  "DOS 3.3+ secondary partition",
  "Reserved",
  "Prologue single-volume partition",
  "Prologue multi-volume partition",
  "Storage Dimensions SpeedStor",
  "DDRdrive Solid State File System",
  "Unknown",
  "pCache",
  "Bochs",
  "VMware File System partition",
  "VMware Swap partition",
  "Linux raid partition with autodetect using persistent superblock",
  "Linux Logical Volume Manager partition (old)",
  "Xenix Bad Block Table"
};


DosPartitionNode::DosPartitionNode(std::string name, uint64_t size, Node* parent, Partition* fsobj):  Node(name, size, parent, fsobj)
{
}

DosPartitionNode::~DosPartitionNode()
{
}

Attributes	DosPartitionNode::dataType()
{
  Attributes	dtype;
  Variant*	vptr;

  if (this->__type == UNALLOCATED)
    {
      if ((vptr = new Variant(std::string("unallocated"))) != NULL)
	dtype["partition"] = Variant_p(vptr);
      return dtype;
    }
  else
    return Node::dataType();
}

void	DosPartitionNode::fileMapping(FileMapping* fm)
{
  this->__handler->mapping(fm, this->__entry, this->__type);
}

Attributes	DosPartitionNode::_attributes(void)
{
  return this->__handler->entryAttributes(this->__entry, this->__type);
}

void	DosPartitionNode::setCtx(DosPartition* handler, uint64_t entry, uint8_t type)
{
  this->__handler = handler;
  this->__entry = entry;
  this->__type = type;
}

std::string	DosPartitionNode::icon(void)
{
  if (this->__type == UNALLOCATED)
    return (std::string(":disksfilesystemsdeleted"));
  else
    return (std::string(":disksfilesystems"));
}	

/*
 * ---------------------------------------------
 * Starting implementation of DosPartition class
 * ---------------------------------------------
*/

DosPartition::DosPartition()
{
  this->vfile = NULL;
  this->root = NULL;
  this->origin = NULL;
  this->__logical = 0;
  this->__primary = 0;
  this->__hidden = 0;
  this->__extended = 0;
  this->__slot = 1;
}

DosPartition::~DosPartition()
{
  if (this->vfile != NULL)
    {
      try
	{
	  this->vfile->close();
	  delete this->vfile;
	}
      catch(vfsError e)
	{
	  throw vfsError("Partition error while closing file" + e.error);
	}
    }
}

void		DosPartition::mapping(FileMapping* fm, uint64_t entry, uint8_t type)
{
  metaiterator	mit;
  uint64_t	offset;
  uint64_t	size;
  uint64_t	tsize;
  bool		process;

  process = false;
  if ((type == UNALLOCATED) && ((mit = this->unallocated.find(entry)) != this->unallocated.end()))
    {
      offset = this->offset + mit->first * this->sectsize;
      size = mit->second->entry_offset * this->sectsize;
      process = true;
    }
  else if ((type != UNALLOCATED) && ((mit = this->allocated.find(entry)) != this->allocated.end()))
    {
      offset = this->offset + mit->first * this->sectsize;
      size = (uint64_t)mit->second->pte->total_blocks * this->sectsize;
      process = true;
    }
  if (process)
    {
      //XXX NEED CASE DUMP
      if (offset > this->origin->size())
	fm->push(0, size);
      //XXX NEED CASE DUMP
      else if (offset + size > this->origin->size())
	{
	  tsize = this->origin->size() - offset;
	  fm->push(0, tsize, this->origin, offset);
	  fm->push(tsize, tsize - size);
	}
      else
	fm->push(0, size, this->origin, offset);
    }
}


Attributes	DosPartition::__entryAttributes(metaiterator mit)
{
  Attributes		vmap;
  std::stringstream	ostr;

  if (mit->second->type == UNALLOCATED)
    {
      vmap["starting sector"] = new Variant(mit->first);
      vmap["ending sector"] = new Variant(mit->second->entry_offset - 1);
      vmap["total sectors"] = new Variant(mit->second->entry_offset - mit->first);
      ostr.str("");
      ostr << "Unallocated #" << mit->second->sslot;
      vmap["entry type"] = new Variant(ostr.str());
    }
  else
    {
      vmap["starting sector"] = new Variant(mit->first);
      vmap["ending sector"] = new Variant(mit->first + mit->second->pte->total_blocks - 1);
      vmap["total sectors"] = new Variant(mit->second->pte->total_blocks);
      if (mit->second->pte->status == 0x80)
	vmap["status"] = new Variant(std::string("bootable (0x80)"));
      else if (mit->second->pte->status == 0x00)
	vmap["status"] = new Variant(std::string("not bootable (0x00)"));
      else
	{
	  ostr << "invalid (0x" << std::setw(2) << std::setfill('0') << std::hex << (int)mit->second->pte->status << ")";
	  vmap["status"] = new Variant(ostr.str());
	  ostr.str("");
	}
      ostr.str("");
      if ((mit->second->type & PRIMARY) == PRIMARY)
	ostr << "Primary #";
      else if ((mit->second->type & LOGICAL) == LOGICAL)
	ostr << "Logical #";
      else if ((mit->second->type & EXTENDED) == EXTENDED)
	ostr << "Extended #";
      ostr << mit->second->sslot; 
      if ((mit->second->type & HIDDEN) == HIDDEN)
	ostr << " | Hidden";
      vmap["entry type"] = new Variant(ostr.str());
      ostr.str("");
      ostr << partition_types[mit->second->pte->type] << " (0x" << std::setw(2) << std::setfill('0') << std::hex << (int)mit->second->pte->type << ")";
      vmap["partition type"] = new Variant(ostr.str());
      vmap["entry offset"] = new Variant(mit->second->entry_offset);
    }
  return vmap;
} 

Attributes	DosPartition::entryAttributes(uint64_t entry, uint8_t type)
{
  metaiterator		mit;
  Attributes		vmap;

  if ((type == UNALLOCATED) && ((mit = this->unallocated.find(entry)) != this->unallocated.end()))
    vmap = this->__entryAttributes(mit);
  else if ((type != UNALLOCATED) && ((mit = this->allocated.find(entry)) != this->allocated.end()))
    vmap = this->__entryAttributes(mit);
  return vmap;
}

void		DosPartition::makeResults()
{
  std::stringstream	ostr;
  metaiterator		mit;
  Attributes		metares;
  Attributes		rootext;
  Attributes		unallocres;
  Variant*		vptr;

  
  for (mit = this->allocated.begin(); mit != this->allocated.end(); mit++)
    {
      if ((mit->second->type & EXTENDED) == EXTENDED)
	{
	  ostr.str("");
	  ostr << "Extended #" << mit->second->sslot;
	  if (mit->second->sslot > 1)
	    {
	      if ((vptr = new Variant(this->__entryAttributes(mit))) != NULL)
		metares[ostr.str()] = Variant_p(vptr);
	    }
	  else
	    rootext = this->__entryAttributes(mit);
	}
      else if ((mit->second->type & PRIMARY) == PRIMARY)
	{
	  ostr.str("");
	  ostr << "Primary #" << mit->second->sslot << " (effective slot #" << mit->second->slot << ")";
	  if ((vptr = new Variant(this->__entryAttributes(mit))) != NULL)
	    this->res[ostr.str()] = Variant_p(vptr);
	}
      else
	{
	  ostr.str("");
	  ostr << "Logical #" << mit->second->sslot << " (effective slot #" << mit->second->slot << ")";
	  if ((vptr = new Variant(this->__entryAttributes(mit))) != NULL)
	    rootext[ostr.str()] = Variant_p(vptr);
	}
    }
  for (mit = this->unallocated.begin(); mit != this->unallocated.end(); mit++)
    {
      ostr.str("");
      ostr << "Unallocated #" << mit->second->sslot;
      if ((vptr = new Variant(this->__entryAttributes(mit))) != NULL)
	unallocres[ostr.str()] = Variant_p(vptr);
    }
  if (metares.size() && ((vptr = new Variant(metares)) != NULL))
    this->res["Meta"] = Variant_p(vptr);
  if (unallocres.size() && ((vptr = new Variant(unallocres)) != NULL))
    this->res["Unalloc"] = Variant_p(vptr);
  if (rootext.size() && ((vptr = new Variant(rootext)) != NULL))
    this->res["Extended #1"] = Variant_p(vptr);
}

Attributes	DosPartition::result()
{
  return this->res;
}

void	DosPartition::open(Node* origin, uint64_t offset, uint32_t sectsize, Partition* fsobj) throw (vfsError)
{
  this->__slot = 1;
  this->__primary = 1;
  this->__hidden = 0;
  this->__logical = 1;
  this->__extended = 1;
  this->origin = origin;
  this->offset = offset;
  this->sectsize = sectsize;
  this->fsobj = fsobj;
  this->root = fsobj->root;
  this->vfile = this->origin->open();
  try
    {
      this->readMbr();
    }
  catch (vfsError err)
    {
    }
  this->makeUnallocated();
  this->makeNodes();
  this->makeResults();
}

dos_pte*	DosPartition::toPte(uint8_t* buff)
{
  dos_pte*	pte;
  uint32_t	lba;
  uint32_t	total_blocks;

  memcpy(&lba, buff+8, 4);
  memcpy(&total_blocks, buff+12, 4);
  //XXX try to used CHS instead ! Need geometry
  if ((lba == 0) && (total_blocks == 0))
    return NULL;
  else
    {
      pte = new dos_pte;
      memcpy(pte, buff, 8);
      pte->lba = lba;
      pte->total_blocks = total_blocks;
      return pte;
    }
}

// std::cout << mit->first << " -- " << mit->first + mit->second->pte->total_blocks - 1 << " -- " << mit->second->pte->total_blocks 
// 	  << " -- EXTENDED" << std::endl;

void	DosPartition::makeNodes()
{
  std::stringstream	ostr;
  metaiterator		mit;
  DosPartitionNode*	pnode;
  Node*			root_unalloc;
  uint64_t		size;

  if (this->allocated.size() > 0)
    {
      for (mit = this->allocated.begin(); mit != this->allocated.end(); mit++)
	{
	  if ((mit->second->type & EXTENDED) != EXTENDED)
	    {
	      ostr << "Partition " << mit->second->slot;
	      size = (uint64_t)mit->second->pte->total_blocks * this->sectsize;
	      pnode = new DosPartitionNode(ostr.str(), size, this->root, this->fsobj);
	      pnode->setCtx(this, mit->first, mit->second->type);
	      ostr.str("");
	      // std::cout << mit->first << " -- " << mit->first + mit->second->pte->total_blocks - 1 << " -- " << mit->second->pte->total_blocks 
	      // 		<< " -- " <<  partition_types[mit->second->pte->type] << std::endl;
	    }
	}
    }
  if (this->unallocated.size() > 0)
    {
      root_unalloc = new Node("Unallocated", 0, this->root, this->fsobj);
      if (root_unalloc != NULL)
	{
	  for (mit = this->unallocated.begin(); mit != this->unallocated.end(); mit++)
	    {
	      ostr << mit->first << "s--" << mit->second->entry_offset - 1 << "s";
	      size = (mit->second->entry_offset - mit->first) * this->sectsize;
	      pnode = new DosPartitionNode(ostr.str(), size, root_unalloc, this->fsobj);
	      pnode->setCtx(this, mit->first, UNALLOCATED);
	      ostr.str("");
	    }
	      //std::cout << mit->first << " -- " << mit->second->entry_offset - 1 << " -- " << mit->second->entry_offset - mit->first << " -- UNALLOCATED" << std::endl;
	 }
      }
    
}

void	DosPartition::makeUnallocated()
{
  std::map<uint64_t, metadatum*>::iterator	mit;
  metadatum*					meta;
  uint64_t					sidx;
  uint32_t					counter;

  sidx = 0;
  counter = 1;
  for (mit = this->allocated.begin(); mit != this->allocated.end(); mit++)
    {
      if ((mit->second->type & EXTENDED) != EXTENDED)
	{
	  if (mit->first > sidx)
	    {
	      meta = new metadatum;
	      meta->pte = NULL;
	      meta->entry_offset = mit->first;
	      meta->type = UNALLOCATED;
	      meta->slot = (uint32_t)-1;
	      meta->sslot = counter++;
	      this->unallocated[sidx] = meta;
	    }
	  sidx = mit->first + mit->second->pte->total_blocks;
	}
    }
  if ((this->offset + (sidx * this->sectsize)) < this->origin->size())
    {
      meta = new metadatum;
      meta->pte = NULL;
      meta->entry_offset = ((this->origin->size() - this->offset) / this->sectsize);
      meta->type = UNALLOCATED;
      meta->sslot = counter++;
      meta->slot = (uint32_t)-1;
      this->unallocated[sidx] = meta;
    }  
}

void	DosPartition::readMbr() throw (vfsError)
{
  dos_partition_record	record;
  uint8_t		i;
  dos_pte*		pte;
  uint32_t		disk_sig;
  Attributes		mbrattr;
  metadatum*		meta;

  this->vfile->seek(this->offset);
  if (this->vfile->read(&record, sizeof(dos_partition_record)) > 0)
    {
      if (record.signature != 0xAA55)
	mbrattr["signature"] = new Variant(std::string("Not setted"));
      else
	mbrattr["signature"] = new Variant(record.signature);
      memcpy(&disk_sig, record.a.mbr.disk_signature, 4);
      mbrattr["disk signature"] = new Variant(disk_sig);
      this->res["mbr"] = new Variant(mbrattr);
      for (i = 0; i != 4; i++)
	{
	  if ((pte = this->toPte(record.partitions+(i*16))) != NULL)
	    {
	      meta = new metadatum;
	      meta->pte = pte;
	      meta->entry_offset = this->offset + 446 + i * 16;
	      if (IS_EXTENDED(pte->type))
	      	{
		  meta->slot = (uint32_t)-1;
		  meta->sslot = this->__extended++;
		  meta->type = EXTENDED;
	      	  this->ebr_base = pte->lba;
	      	  this->readEbr(pte->lba);
	      	}
	      else
		{
		  meta->slot = this->__slot++;
		  meta->sslot = this->__primary++;
		  meta->type = PRIMARY;
		}
	      this->allocated[pte->lba] = meta;
	    }
	}
    }
}

void	DosPartition::readEbr(uint64_t csector, uint64_t shift) throw (vfsError)
{
  dos_partition_record	record;
  uint8_t		i;
  dos_pte*		pte;
  uint64_t		offset;
  metadatum*		meta;

  offset = this->offset + csector*this->sectsize;
  this->vfile->seek(offset);
  if (this->vfile->read(&record, sizeof(dos_partition_record)) > 0)
    {
      for (i = 0; i != 4; i++)
	{
	  if ((pte = this->toPte(record.partitions+(i*16))) != NULL)
	    {
	      if (IS_EXTENDED(pte->type))
		{
		  if ((this->ebr_base + pte->lba) != csector)
		    {
		      meta = new metadatum;
		      meta->pte = pte;
		      meta->entry_offset = offset + 446 + i * 16;
		      meta->slot = (uint32_t)-1;
		      meta->sslot = this->__extended++;
		      if (i > 2)
			{
			  this->__hidden++;
			  meta->type = EXTENDED|HIDDEN;
			}
		      else
			meta->type = EXTENDED;
		      this->allocated[this->ebr_base + pte->lba] = meta;
		      this->readEbr(this->ebr_base + (uint64_t)(pte->lba), pte->lba);
		    }
		  else
		    ;
		}
	      else
		{
		  meta = new metadatum;
		  meta->pte = pte;
		  meta->entry_offset = offset + 446 + i * 16;
		  meta->slot = this->__slot++;
		  meta->sslot = this->__logical++;
		  if (i > 2)
		    {
		      this->__hidden++;
		      meta->type = LOGICAL|HIDDEN;
		    }
		  else
		    meta->type = LOGICAL;
		  this->allocated[this->ebr_base + shift + pte->lba] = meta;
		}
	    }
	}
    }
}
