# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.
#  
# See http://www.digital-forensic.org for more information about this
# project. Please do not directly contact any of the maintainers of
# DFF for assistance; the project provides a web site, mailing lists
# and IRC channels for your use.
# 
# Author(s):
#  Romain Bertholon <rbe@digital-forensic.org>
# 
import unicodedata

from datetime import datetime
from decoder import *

from dff.api.types.libtypes import VList

MD_SB_GENERIC_CONSTANT_WORDS = 32
MD_SB_GENERIC_STATE_WORDS = 32
MD_SB_PERSONALITY_WORDS = 64
MD_SB_DESCRIPTOR_WORDS = 32
MD_SB_DISKS = 27
MD_SB_DISKS_WORDS = (MD_SB_DISKS * MD_SB_DESCRIPTOR_WORDS)
MD_SB_GENERIC_WORDS = (MD_SB_GENERIC_CONSTANT_WORDS + MD_SB_GENERIC_STATE_WORDS)
MD_SB_RESERVED_WORDS = (1024 - MD_SB_GENERIC_WORDS - MD_SB_PERSONALITY_WORDS \
                            - MD_SB_DISKS_WORDS - MD_SB_DESCRIPTOR_WORDS)

MD_SUPERBLOCK = {
    # constant array information - 128 bytes #
    "magic":[0, 0x4, UINT32_T],		# MD_SB_MAGIC: 0xa92b4efc - little endian #
    "major_version":[4, 0x4, UINT32_T],	# 1 #
    "feature_map":[8, 0x4, UINT32_T],	# 0 for now #
    "pad0":[12, 0x4, UINT32_T],		# always set to 0 when writing #
    "set_uuid":[16, 16, STRING_T],
    "set_name":[32, 32, STRING_T],
    "ctime":[64, 0x8, UINT64_T],		# lo 40 bits are seconds, top 24 are microseconds or 0#
    "level":[72, 0x4, UINT32_T],		# -4 (multipath), -1 (linear), 0,1,4,5 #
    "layout":[76, 0x4, UINT32_T],		# only for raid5 currently #
    "size":[80, 0x8, UINT64_T],		# used size of component devices, in 512byte sectors #

    "chunksize":[88, 0x4, UINT32_T],	# in 512byte sectors #
    "raid_disks":[92, 0x4, UINT32_T],
    
    # sectors after start of superblock that bitmap starts
    # NOTE: signed, so bitmap can be before superblock
    # only meaningful of feature_map[0] is set.
    "bitmap_offset":[96, 0x4, UINT32_T],


    # These are only valid with feature bit '4' #
    "new_level":[100, 0x4, UINT32_T],	# new level we are reshaping to		#
    "reshape_position":[104, 0x8, UINT64_T],	# next address in array-space for reshape #
    "delta_disks":[112, 0x4, UINT32_T],	# change in number of raid_disks		#
    "new_layout":[116, 0x4, UINT32_T],	# new layout					#
    "new_chunk":[120, 0x4, UINT32_T],	# new chunk size (bytes)			#

    "pad":[124, 0x4, STRING_T],

    # constant this-device information - 64 bytes #
    "data_offset":[128, 0x8, UINT64_T],	# sector start of data, often 0 #
    "data_size":[136, 0x8, UINT64_T],	# sectors in this device that can be used for data #
    "super_offset":[144, 0x8, UINT64_T],	# sector start of this superblock #
    "recovery_offset":[152, 0x8, UINT64_T],# sectors before this offset (from data_offset) have been recovered #
    "dev_number":[160, 0x4, UINT32_T],	# permanent identifier of this  device - not role in raid #
    "cnt_corrected_read":[164, 0x4, UINT32_T], # number of read errors that were corrected by re-writing #
    "device_uuid":[168, 16, STRING_T], # user-space setable, ignored by kernel #
    "devflags":[184, 0x1, UINT8_T],        # per-device flags.  Only one defined...#

    #define WriteMostly1    1        # mask for writemostly flag in above #
    "pad2":[185, 0x7, STRING_T],	# set to 0 when writing #

    # array state information - 64 bytes #
    "utime":[192, 0x8, UINT64_T],		# 40 bits second, 24 btes microseconds #
    "events":[200, 0x8, UINT64_T],		# incremented when superblock updated #
    "resync_offset":[208, 0x8, UINT64_T],	# data before this offset (from data_offset) known to be in sync #
    "sb_csum":[216, 0x4, UINT32_T],	# checksum upto dev_roles[max_dev] #
    "max_dev":[220, 0x4, UINT32_T],	# size of dev_roles[] array to consider #
    "pad3":[224, 0x20, STRING_T],	# set to 0 when writing #
}

class   MdSuperblock(decoder):
    def __init__(self, vfile, offset, template):
        decoder.__init__(self, vfile, offset, template)
        
