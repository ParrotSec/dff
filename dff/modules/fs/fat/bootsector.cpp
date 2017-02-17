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

#include "bootsector.hpp"

BootSector::BootSector()
{
  this->errlog = "";
  this->err = 0;
}

BootSector::~BootSector()
{
}

void	BootSector::process(Node *origin, class Fatfs* fs)
{
  this->fs = fs;
  this->origin = origin;
  try
    {
      this->vfile = this->origin->open();
      if (this->vfile->read(&(this->bs), sizeof(bootsector)) == 512)
	this->fillCtx();
      else
	throw(std::string("cannot read boot sector"));
      this->vfile->close();	
    }
  catch(...)
    {
      this->vfile->close();	
      throw("err");
    }
}

void	BootSector::fillSectorSize()
{
  this->ssize = *((uint16_t*)this->bs.ssize);
  if ((this->ssize != 512) &&
      (this->ssize != 1024) &&
      (this->ssize != 2048) &&
      (this->ssize != 4096))
    {
      this->errlog += "invalid sector size field\n";
      this->err |= BADSSIZE;
    }
}

void	BootSector::fillClusterSize()
{
  this->csize = this->bs.csize;
  if ((this->csize != 0x01) &&
      (this->csize != 0x02) &&
      (this->csize != 0x04) &&
      (this->csize != 0x08) &&
      (this->csize != 0x10) &&
      (this->csize != 0x20) &&
      (this->csize != 0x40) && 
      (this->csize != 0x80))
    {
      this->errlog += "invalid cluster size field\n";
      this->err |= BADCSIZE;
    }
}

void   BootSector::fillTotalSector()
{
  uint16_t	sectors16;
  uint32_t	sectors32;

  sectors16 = *((uint16_t*)this->bs.sectors16);
  sectors32 = *((uint32_t*)this->bs.sectors32);
  if (sectors16 != 0)
    this->totalsector = (uint32_t)sectors16;
  else if (sectors32 != 0)
    this->totalsector = sectors32;
  else
    {
      this->errlog += "total sector field not defined\n";
      this->err |= BADTOTALSECTOR;
    }
//   if (this->totalsector * this->ssize > this->node->size())
//     this->warnlog.push_back("total sector size ");
}

void	BootSector::fillTotalSize()
{
  // uint32_t	missingsect;

  // missingsect = 0;
  if (((this->err & BADTOTALSECTOR) != BADTOTALSECTOR) && ((this->err & BADSSIZE) != BADSSIZE))
    {
      this->totalsize = (uint64_t)this->totalsector * (uint64_t)this->ssize;
      if (this->totalsize > this->origin->size())
	{
	  //missingsect = (this->totalsize - this->origin->size()) / (uint64_t)this->ssize;
	  this->errlog += "total size exceeds node size\n";
	}
    }
}

void	BootSector::fillReserved()
{
  this->reserved = *((uint16_t*)this->bs.reserved);
  if (((this->err & BADTOTALSECTOR) != BADTOTALSECTOR) && (this->reserved > this->totalsector))
    {
      this->errlog += "number of reserved sector(s) exceeds total number of sectors\n";
      this->err |= BADRESERVED;
    }
}

//if numfat setted to 0, search for FAT pattern
void	BootSector::fillSectorPerFat()
{
  uint16_t	sectperfat16;
  uint32_t	sectperfat32;

  this->sectperfat = 0;
  sectperfat16 = *((uint16_t*)this->bs.sectperfat16);
  sectperfat32 = *((uint32_t*)this->bs.a.f32.sectperfat32);
  if (sectperfat16 != 0)
    this->sectperfat = (uint32_t)sectperfat16;
  else if (sectperfat32 != 0)
    this->sectperfat = sectperfat32;
  else
    {
      this->errlog += "total sector per fat not defined\n";
      this->err |= BADSECTPERFAT;
    }
  if (((this->err & BADTOTALSECTOR) != BADTOTALSECTOR) && (this->sectperfat > this->totalsector))
    {
      this->errlog += "total number of sector(s) per fat exceeds total number of sectors\n";
      this->err |= BADSECTPERFAT;
    }
}

void	BootSector::fillNumberOfFat()
{
  this->numfat = this->bs.numfat;
  if (this->numfat == 0)
    {
      this->errlog += "number of fat not defined\n";
      this->err |= BADNUMFAT;
    }
  if (((this->err & BADTOTALSECTOR) != BADTOTALSECTOR) && 
      ((this->err & BADSECTPERFAT) != BADSECTPERFAT) &&
      ((this->numfat * this->sectperfat) > this->totalsector))
    {
      this->errlog += "total number of sector allocated for FAT(s) exceeds total number of sectors\n";
      this->err |= BADNUMFAT;
    }
}

void	BootSector::fillNumRoot()
{
  this->numroot = *((uint16_t*)this->bs.numroot);
//   if (((this->fattype == 12) || (this->fattype == 16)) && (this->numroot < 2)) // . and .. entries
//     {
//       this->err |= BADNUMROOT;
//       this->errlog += "total number of entries in root directory less than 2 (. and .. entries)\n";
//     }
//   else if (((this->numroot * 32) / this->ssize) > this->totalsector)
//     {
//       this->err |= BADNUMROOT;
//       this->errlog += "total number of entries in root directory exceeds total number of sector\n";
//     }
}

void		BootSector::fillFatType()
{
  this->rootdirsector = ((this->numroot * 32) + (this->ssize - 1)) / this->ssize;
  this->rootdirsize = (this->numroot * 32);
  this->datasector = this->reserved + (this->numfat * this->sectperfat) + this->rootdirsector;
  this->totaldatasector = this->totalsector - (this->reserved + (this->numfat * this->sectperfat) + this->rootdirsector);
  this->totalcluster = this->totaldatasector / this->csize;
  this->firstfatoffset = this->reserved * this->ssize;

  if(this->totalcluster < 4085)
    this->fattype = 12;
  else if(this->totalcluster < 65525)
    this->fattype = 16;
  else
    this->fattype = 32;
}

void	BootSector::fillExtended()
{
  this->totalsize = (uint64_t)this->totalsector * this->ssize;
  this->totaldatasize = (uint64_t)this->totaldatasector * this->ssize;
  if (this->fattype == 32)
    {
      this->vol_id = *((uint32_t*)this->bs.a.f32.vol_id);
      memcpy(this->vol_lab, this->bs.a.f32.vol_lab, 11);
      memcpy(this->fs_type, this->bs.a.f32.fs_type, 8);
      this->rootclust = *((uint32_t*)this->bs.a.f32.rootclust);
      this->ext_flag = *((uint16_t*)this->bs.a.f32.ext_flag);
      this->fs_ver = *((uint16_t*)this->bs.a.f32.fs_ver);
      this->fsinfo = *((uint16_t*)this->bs.a.f32.fsinfo);
      this->bs_backup = *((uint16_t*)this->bs.a.f32.bs_backup);
      this->drvnum = this->bs.a.f32.drvnum;
      this->rootdiroffset = ((this->rootclust - 2) * this->csize) + this->datasector * this->ssize;
      this->dataoffset = this->reserved * this->ssize + this->fatsize * this->numfat;
    }
  else
    {
      this->vol_id = *((uint32_t*)this->bs.a.f16.vol_id);
      memcpy(this->vol_lab, this->bs.a.f16.vol_lab, 11);
      memcpy(this->fs_type, this->bs.a.f16.fs_type, 8);
      this->rootdiroffset = this->firstfatoffset + this->fatsize * this->numfat;
      this->dataoffset = this->firstfatoffset + this->fatsize * this->numfat + rootdirsector * this->ssize;
    }
}

void	BootSector::fillCtx()
{
  memcpy(this->oemname, this->bs.oemname, 8);
  this->fillSectorSize();
  this->fillClusterSize();
  this->fillTotalSector();
  this->fillReserved();
  this->fillSectorPerFat();
  this->fillNumberOfFat();
  this->fillNumRoot();
  this->prevsect = *((uint32_t*)this->bs.prevsect);
  if (this->err != 0)
    {
      //std::cout << "error: " << this->errlog << std::endl;
      throw("bad bootsector");
    }
  else
    {
      this->fatsize = this->sectperfat * this->ssize;
      this->fillFatType();
      this->fillExtended();
      this->fs->res["fat type"] = Variant_p(new Variant(this->fattype));
      this->fs->res["oemname"] = Variant_p(new Variant(this->oemname));
      this->fs->res["sector size"] = Variant_p(new Variant(this->ssize));
      this->fs->res["sectors per cluster"] = Variant_p(new Variant(this->csize));
      this->fs->res["reserved cluster"] = Variant_p(new Variant(this->reserved));
      this->fs->res["number of fat"] = Variant_p(new Variant(this->numfat));
      this->fs->res["number of entries in root directory"] = Variant_p(new Variant(this->numroot));
      this->fs->res["number of sectors before FS partition"] = Variant_p(new Variant(this->prevsect));
      this->fs->res["volume id"] = Variant_p(new Variant(this->vol_id));
      this->fs->res["volume label"] = Variant_p(new Variant(this->vol_lab));
      this->fs->res["FS type"] = Variant_p(new Variant(this->fs_type));
      this->fs->res["root cluster"] = Variant_p(new Variant(this->rootclust));
      this->fs->res["total sectors for data"] = Variant_p(new Variant(this->totaldatasector));
      this->fs->res["total sectors"] = Variant_p(new Variant(this->totalsector));
      this->fs->res["sectors per fat"] = Variant_p(new Variant(this->sectperfat));
      this->fs->res["total clusters"] = Variant_p(new Variant(this->totalcluster));
      this->fs->res["first sector of root directory"] = Variant_p(new Variant(this->rootdirsector));
      this->fs->res["offset of first fat"] = Variant_p(new Variant(this->firstfatoffset));
      this->fs->res["offset of root directory"] = Variant_p(new Variant(this->rootdiroffset));
      this->fs->res["size of root directory"] = Variant_p(new Variant(this->rootdirsize));
      this->fs->res["start offset of data"] = Variant_p(new Variant(this->dataoffset));
      this->fs->res["first sector of data"] = Variant_p(new Variant(this->datasector));
      this->fs->res["size of fat"] = Variant_p(new Variant(this->fatsize));
      this->fs->res["total size"] = Variant_p(new Variant(this->totalsize));
      this->fs->res["total data size"] = Variant_p(new Variant(this->totaldatasize));
    }
}

//Further implementation:
// - create translation based on endianness
// void	BootSector::createCtx()
// {
//    uint32_t	rootdirsector;


// }

// bool	bootSector::DetermineFatType()
// {

// }

// bsctx*		bootSector::getBootSectorContext()
// {
//   return (this->ctx);
// }
