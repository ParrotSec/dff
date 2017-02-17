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

#ifndef __BOOT_HPP__
#define __BOOT_HPP__

#include "mfso.hpp"
#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif

#ifdef WIN32
#define PACK
#else
#define PACK __attribute__((packed))
#endif

#define	BOOT_BLOCK_SIZE			512
#define BOOT_MEDIA_DESCRIPTOR_ID	"NTFS    "
#define	BOOT_FAT_NTFS_SIGNATURE		0xAA55

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct	s_BootBlock
{
  uint8_t       jmpLoaderRoutine[3];
  char		mediaDescriptorId[8];
  uint16_t	bytePerSector;
  uint8_t	sectorPerCluster;
  uint8_t	unused1[2];	// reservedSectors, Microsoft says it must be 0
  uint8_t	unused2[5];	// Microsoft says it must be 0
  uint8_t	mediaDescriptor;
  uint8_t	unused3[2];	// Microsoft says it must be 0
  uint8_t	unused4[8];	// Microsoft says it is not checked (uint16_t sectorByTrack and uint16_t numberOfHead ?!?)
  uint8_t	unused5[4];	// Microsoft says it must be 0
  uint8_t	unused6[4];	// Microsoft says it is not checked
  uint64_t	numberOfSector;
  uint64_t	startMft;
  uint64_t	startMftMirr;
  uint8_t	clusterMftRecord;	// size of one file record (MFT entry)
  uint8_t	unused7[3];
  uint8_t	clusterIndexRecord;	// size of Index record
  uint8_t	unused8[3];
  uint64_t	volumeSerialNumber;
  uint8_t	unused9[4];
  uint8_t	bootCode[426];
  uint16_t	signature;	// BOOT_FAT_NTFS_SIGNATURE
}		PACK BootBlock;

class Boot
{
public:
  Boot(VFile *);
  ~Boot();
  bool		isBootBlock(uint64_t offset);
  BootBlock	*getBootBlock();
  void		setBootBlock(BootBlock *);
  void		mftEntrySize(uint16_t size) { _mftEntrySize = size; };
  uint16_t	mftEntrySize() { return _mftEntrySize; };
  bool		isPow2(int);
  uint16_t	indexRecordSize() { return _bootBlock->clusterIndexRecord * _clusterSize; };
  uint16_t	sectorSize() { return _bootBlock->bytePerSector; };
  uint16_t	clusterSize() { return _clusterSize; };

private:
  BootBlock	*_bootBlock;
  VFile		*_vfile;
  uint16_t	_clusterSize;
  uint16_t	_mftEntrySize;
  uint16_t	_indexRecordSize;
};

#endif
