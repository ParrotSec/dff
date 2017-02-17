__dff_module_testapsw_version__ = "1.0.0"

import apsw
from struct import unpack

from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.types.libtypes import Variant, VList, VMap, Argument, Parameter, typeId
from dff.api.apswvfs import apswvfs

from dff.api.module.manager import ModuleProcessusManager

from sqlitemanager import SqliteManager 

ModuleProcessusManager().register(SqliteManager('SqliteDB'))

class SqliteDB(Script):
    def __init__(self):
        Script.__init__(self, "SqliteDB")
        self.name = "SqliteDB"

    def start(self, args):     
       self.node = args["node"].value()
       avfs = apswvfs.apswVFS()
       self.db = apsw.Connection(self.node.absolute(), vfs = avfs.vfsname)

    def execute(self, cmd):
       try:
           c = self.db.cursor()
           c.execute("PRAGMA locking_mode=EXCLUSIVE;")	
           c.execute(cmd)
           return c
       except:
           return None


class sqlitedb(Module):
    """Allows to query sqlite database trough the VFS"""
    def __init__(self):
        Module.__init__(self, "sqlitedb", SqliteDB) 
        self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Node,
                               "name": "node",
                               "description": "sqlite base wrapper."
                               })
	self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["SQLite"]})
        self.tags = "Databases"
