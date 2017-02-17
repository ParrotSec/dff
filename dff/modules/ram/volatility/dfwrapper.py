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
#  Solal Jacob <sja@digital-forensic.org>
#

from datetime import *
from vutils import *
from forensics.win32.tasks import *
from forensics.win32.handles import *
from forensics.win32.executable import rebuild_exe_dsk,rebuild_exe_mem
from forensics.win32.network import *

from dff.api.vfs import *
from dff.api.module.module import *
from dff.api.types.libtypes import Variant, VMap, vtime
from dff.api.vfs.libvfs import *
from dff.api.exceptions import *

class NodeProcessus(Node):
  def __init__(self, name, ssize, mfso, parent, pid = None):
     self.mfso = mfso
     self.ssize = 0
     self.active_threads = None
     self.inherited_from = None
     self.handle_count = None
     self.create_time = None 
     self.connections = None
     self.pid = pid
     Node.__init__(self, name, self.ssize, parent, mfso)
     self.__disown__()
     self.setFile()
     setattr(self, "addMapping", self.addMapping)
     self.virtMapping = []
     setattr(self, "fileMapping", self.fileMapping)

  def fileMapping(self, fm):
     noffset = 0
     for (offset , size) in self.virtMapping:
       fm.push(noffset, size, self.mfso.node, offset) 
       noffset += size
 
  def addMapping(self, offset, size): 
     self.virtMapping.append((offset, size))
     self.ssize += size
     self.setSize(self.ssize)

  def _attributes(self):
      attr = VMap()
      if self.pid != None:
        attr["pid"] = Variant(self.pid)
      if self.active_threads:
        attr["threads"] = Variant(self.active_threads)
      if self.inherited_from:
        attr["ppid"] = Variant(self.inherited_from)
      if self.handle_count:
        attr["handle count"] = Variant(self.handle_count)
      if self.connections:
        attr["connection"] = Variant(self.connections)
      if self.create_time:
       at = vtime() 
       at.thisown = False
       d = datetime.fromtimestamp(self.create_time).timetuple()
       at.year = d[0]
       at.month = d[1]
       at.day = d[2]
       at.hour = d[3]
       at.minute = d[4]
       at.second = d[5]
       at.usecond = 0
       attr["creation"] = Variant(at)
      return attr

  def setMeta(self, active_threads, inherited_from, handle_count, create_time):
     self.active_threads = active_threads 
     self.inherited_from = inherited_from
     self.handle_count = handle_count
     self.create_time = create_time

  def setConnections(self, connections):
     self.connections = connections

class processus():
  def __init__(self, mfso, task, nodename, addr_space, types, symtab):
     self.mfso = mfso
     self.nodename = nodename
     self.task = task
     self.addr_space = addr_space
     self.types = types
     self.symtab = symtab
     self.image_file_name = process_imagename(self.addr_space, self.types, self.task)
     self.process_id = process_pid(self.addr_space, self.types, self.task)
     if self.image_file_name is None:
       if self.process_id != None:
        self.image_file_name = "Process-" + str(self.process_id) 
       else:
        self.image_file_name = "Process-Unknown" 
     if self.process_id != None:
       self.node = NodeProcessus(self.image_file_name, 0, mfso, mfso.root)
     else:
       self.node = NodeProcessus(self.image_file_name, 0, mfso, mfso.root, self.process_id)

  def getMeta(self):
    active_threads = process_num_active_threads(self.addr_space, self.types, self.task)
    inherited_from = process_inherited_from(self.addr_space, self.types, self.task)
    handle_count = process_handle_count(self.addr_space, self.types, self.task)
    create_time = process_create_time(self.addr_space, self.types, self.task)
    self.node.setMeta(active_threads, inherited_from, handle_count, create_time) 

  def getConnections(self):
     connections = tcb_connections(self.addr_space, self.types, self.symtab)
     for connection in connections:
	if not self.addr_space.is_valid_address(connection):
	    continue

        pid     = connection_pid(self.addr_space, self.types, connection)
        if self.process_id == pid:
          lport   = connection_lport(self.addr_space, self.types, connection)
          laddr   = connection_laddr(self.addr_space, self.types, connection)
  	  rport   = connection_rport(self.addr_space, self.types, connection)
	  raddr   = connection_raddr(self.addr_space, self.types, connection)

          local = "%s:%d"%(laddr,lport)
	  remote = "%s:%d"%(raddr,rport)
  
          cnx =  "%-25s---> %-25s"%(local,remote)
          self.node.setConnections(cnx) 

  def dump(self, mode = "disk"):
    mode = "disk"
    if mode == "disk":
      rebuild_exe = rebuild_exe_dsk
    elif mode == "mem":
      rebuild_exe = rebuild_exe_mem

      directory_table_base = process_dtb(self.addr_space, self.types, self.task)
      process_address_space = create_addr_space(self.addr_space, directory_table_base)
      if process_address_space is None:
         return "Error obtaining address space for process [%d]" % (self.process_id)

      image_file_name = process_imagename(process_address_space, self.types, self.task)
      peb = process_peb(process_address_space, self.types, self.task)
      img_base = read_obj(process_address_space, self.types, ['_PEB', 'ImageBaseAddress'], peb)

      if img_base == None:
        return "Error: Image base not memory resident for process [%d]" % (self.process_id)

      if process_address_space.vtop(img_base) == None:
        return "Error: Image base not memory resident for process [%d]" % (self.process_id)

      try:
        rebuild_exe(process_address_space, self.types, img_base, self.node)
      except ValueError,ve:
         return "Unable to dump executable; sanity check failed: " + ve + "You can use -u to disable this check."

  def addEntryNode(self, entry):
      if not self.addr_space.is_valid_address(entry):
      	  return

      obj = handle_entry_object(self.addr_space, self.types, entry)
      if self.addr_space.is_valid_address(obj):
          if is_object_file(self.addr_space, self.types, obj):
              file = object_data(self.addr_space, self.types, obj)
              fname = file_name(self.addr_space, self.types, file)
              if fname != "":
	          fname = fname.replace("\\", "/")
          	  fname = fname.split('/')
                  current_node = self.node
                  for n in fname:
		    if n != '':
                      exist = None
                      children = current_node.children() 
                      for c in children:
			if n == c.name():
                         exist = c
                      if exist:
			current_node = exist
                      else:
			new_node = Node(n)
			new_node.__disown__()
                        current_node.addChild(new_node)
                        current_node = new_node                         
                       


  def getOpenFiles(self):
      """
      Creates node for each open files for each process.
      """
      htables = []    

      htables = handle_tables(self.addr_space, self.types, self.symtab, self.process_id)
      for table in htables:

          process_id = handle_process_id(self.addr_space, self.types, table)
	  if process_id == None:
	    continue
        
          table_code = handle_table_code(self.addr_space, self.types, table)
          if table_code == 0:
   	    continue

          table_levels = handle_table_levels(self.addr_space, self.types, table)
          if table_levels == 0:
            num_entries = handle_num_entries(self.addr_space, self.types, table)
	    for counter in range(0, 0x200):
                entry = handle_table_L1_entry(self.addr_space, self.types, table, counter)
		if entry != None and entry !=0:
                    self.addEntryNode(entry)                
                        
          elif table_levels == 1:
            for i in range(0, 0x200):
                L1_entry = handle_table_L1_entry(self.addr_space, self.types, table, i)
                if not L1_entry is None:
                    L1_table = handle_entry_object(self.addr_space, self.types, L1_entry)

                    for j in range(0, 0x200):
                        L2_entry = handle_table_L2_entry(self.addr_space, self.types, table, L1_table, j)
                        if not L2_entry is None:
                            self.addEntryNode(L2_entry)

          elif table_levels == 2:
            for i in range(0, 0x200):
                L1_entry = handle_table_L1_entry(self.addr_space, self.types, table, i)
                if not L1_entry is None:
                    L1_table = handle_entry_object(L1_entry)

                    for j in range(0, 0x200):
                        L2_entry = handle_table_L2_entry(self.addr_space, self.types, table, L1_table, j)
                        if not L2_entry is None:
                            L2_table = handle_entry_object(self.addr_space, self.types, L2_entry)
                            
                            for k in range(0, 0x200):
                                L3_entry = handle_table_L3_entry(self.addr_space, self.types, table, L2_table, j)
                                if not L3_entry is None:                  
                                    self.addEntryNode(self.addr_space, self.types, L3_entry)                            


class op():
 def __init__(self, node):
   self.node = node
   self.filename = node.absolute()
   self.base = None
   self.type = None

 def error(self, msg):
    print msg

