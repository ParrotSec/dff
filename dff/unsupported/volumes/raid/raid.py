# DFF -- An Open Source Digital Forensics Framework
#
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
#  Romain Bertholon < rbe@digital-forensic.org>
#
__dff_module_winreg_version__ = "1.0.0"

import datetime

from header import MdSuperblock, MD_SUPERBLOCK

from dff.api.vfs import *
from dff.api.module.module import *
from dff.api.types.libtypes import Argument, typeId
from dff.api.vfs.libvfs import *

class Raid1Node(Node):
    def __init__(self, name, size, node, mfso, sb):
        Node.__init__(self, name, size, node.parent(), mfso)
        self.__disown__()
        self.sb = sb
        self.node = node

    def fileMapping(self, fm):
        fm.push(0, self.node.size() - self.sb.data_offset * 512,\
                    self.node, self.sb.data_offset * 512)

class RAID(mfso):
    def __init__(self):
        mfso.__init__(self, "raid")
        self.name = "raid"
        self.__disown__()
        self.node = None

    def start(self, args):
       vol1 = args['volume1'].value()
       vol2 = args['volume2'].value()
    
       vfile = vol1.open()
       super_block = MdSuperblock(vfile, 4096, MD_SUPERBLOCK)
       self.dispInfo(super_block)
      
       if super_block.level == 1:
           self.node = Raid1Node('raid_volume', super_block.data_size, vol1,\
                                     self, super_block)
       else:
           print "Raid %d not handled." % (sb.level, )
 
       vfile.close()

    def dispInfo(self, sb):
        print ""
        print "Magic :", hex(sb.magic)
        print "  - Feature map :", hex(sb.feature_map)
        print "  - Name :", sb.set_name
        print "  - Creation time : ", datetime.datetime.fromtimestamp(sb.ctime).strftime('%Y-%m-%d %H:%M:%S')

        tmp = ""
        for i in sb.set_uuid:
            tmp += hex(ord(i)).replace('0x', '')
        print "  - Uuid : 0x", tmp

        print ""
        print "Raid level :", sb.level
        print "  - Raid devices :", sb.raid_disks
        print "  - Size :", sb.size
        print "  - Data size :", sb.data_size
        print "  - Data offset :", sb.data_offset
        print "  - Super offset :", sb.super_offset
        print ""
        print "State"
        print "  - Update Time :", datetime.datetime.fromtimestamp(sb.utime).strftime('%Y-%m-%d %H:%M:%S')
        print "  - Events :", sb.events
        print "  - Checksum :", hex(sb.sb_csum)
        print ""

class raid(Module):
  """This modules permit to virtualy reconstruct raid volumes on the VFS."""
  def __init__(self):
    Module.__init__(self, "raid", RAID)
    self.conf.addArgument({"name": "volume1",
                           "description": "raid volume",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "volume2",
                           "description": "raid volume",
                           "input": Argument.Required|Argument.Single|typeId.Node})

    self.tags = "Volumes"
    self.icon = ":database"
