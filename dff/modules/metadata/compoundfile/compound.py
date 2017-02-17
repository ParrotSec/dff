# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
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
#  Solal Jacob <sja@digital-forensic.org>

__dff_module_prefetch_version__ = "1.0.0"

import datetime, sys, traceback

from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.module.manager import ModuleProcessusHandler
from dff.api.vfs.libvfs import AttributesHandler, VFS, mfso
from dff.api.types.libtypes import Argument, typeId, VMap, Variant

from mscfb import CompoundDocumentHeader
from msoleps import  PropertySetStream
from msdoc import WordDocument
from msoshared import OfficeDocumentSectionCLSID
from msppt import PPT


def error():
   err_type, err_value, err_traceback = sys.exc_info()
   for n in  traceback.format_exception_only(err_type, err_value):
     print n
   for n in traceback.format_tb(err_traceback):
     print n

class CompoundDocumentParser(object):
  def __init__(self, node, largs, mfsobj = None):
     self.node = node
     self.attr = {} 
     self.extraAttr = []
     try :    
        self.cdh = CompoundDocumentHeader(node, mfsobj)
	self.cdh.parseDocument(not 'no-extraction' in largs)
     except :
	#error()
	raise Exception("Can't parse document")
     streams = self.cdh.streams()
     for stream in streams:
	if stream.objectType == "StreamObject":
	  try:
	     if stream.objectName == "WordDocument":
	       if not 'no-extraction' in largs:
	         wd = WordDocument(stream)
	         if not 'no-text' in largs:
	           wd.createTextNodes()
	         if not 'no-pictures' in largs:
	           wd.createPictureNodes()
	     elif stream.objectName == "Pictures":
	       if not ('no-pictures' in largs or 'no-extraction' in largs):
	         ppt = PPT(stream)
	         ppt.createPictureNodes()
	     else:
	       propertySet = PropertySetStream(stream, OfficeDocumentSectionCLSID.keys())
	       for clsid in OfficeDocumentSectionCLSID.iterkeys():
	          section = propertySet.sectionCLSID(clsid)
	          if section:
		    (sectionName, sectionIDS) = OfficeDocumentSectionCLSID[clsid]
		    mattr = VMap() 
	            for k, v in sectionIDS.iteritems():
		       Property = section.PropertyList.propertyID(k)
		       if Property and Property.Variant.Value:
		         p = section.PropertyList.propertyID(k).Variant.Value
		         if p and isinstance(p, Variant): #Thumbnail is type node
			   if v == 'Total editing time': #special case see msoshared.py
			     p = Variant(str(datetime.timedelta(seconds=(p.value()/10000000))))
			   else:
			     p = Variant(p)
			   mattr[v] =  p
		    stream.setExtraAttributes((sectionName, mattr,))
		    if not 'no-root_metadata' in largs:	
  		      self.extraAttr.append((sectionName, stream.parent().name(), mattr,))
	  #except RuntimeError, e:
	  #pass	 
          except :
	    #error()
	    pass
        if not 'no-extraction' in largs:
	  del stream 
 
  def _attributes(self):
     vmap = VMap()
     vmap["Compound document"] = self.cdh._attributes()
     for (name, parent, attr) in self.extraAttr:
	vmap[name + ' (' + parent + ')'] = attr
     return vmap	

class MetaCompoundHandler(AttributesHandler, ModuleProcessusHandler):
  def __init__(self):
    AttributesHandler.__init__(self, "metacompound")
    ModuleProcessusHandler.__init__(self, "metacompound")
    self.__disown__()
    self.nodeAttributes = {}
    self.vfs = VFS.Get()
 
  def setAttributes(self, node, classAttributes):
    self.nodeAttributes[long(node.this)] = classAttributes 

  def update(self, processus):
	pass

  def nodes(self, root):
    nodes = []
    rootAbsolute = root.absolute()
    for node in self.nodeAttributes.keys():
	node = self.vfs.getNodeFromPointer(node)
	if node.absolute().find(rootAbsolute) == 0:
	  nodes.append(node)
    return nodes

  def attributes(self, node):
    try:
      classAttributes = self.nodeAttributes[long(node.this)]
      return classAttributes._attributes()
    except KeyError:
      attr = VMap()
      attr.thisown = False
      return attr

class MetaCompound(mfso):
  def __init__(self):
   mfso.__init__(self, 'metacompound')
   self.__disown__()
   self.handler = MetaCompoundHandler()

  def start(self, args):
    try:
      largs = []
      node = args['file'].value()	
      for arg in ['no-extraction', 'no-text', 'no-pictures', 'no-root_metadata']:
	 try:
	   value =  args[arg].value()
	   if value:
	     largs.append(arg)
	 except IndexError:
	     pass
      self.stateinfo = "Registering node: " + str(node.name())
      p = CompoundDocumentParser(node, largs, self)
      self.handler.setAttributes(node, p)
      node.registerAttributes(self.handler)
      self.stateinfo = ""
    except (KeyError, Exception):
      self.stateinfo = "Error"

class compound(Module): 
  """This modules extract metadata and content of compound files (doc,xls,msi, ....).;"""
  def __init__(self):
    Module.__init__(self, "compound", MetaCompound)
    self.conf.addArgument({"name": "file",
                           "description": "file to extract metadata",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "compatible extension",
 	                   "values": ["Composite Document File V2"]})
    self.conf.addArgument({"name": "no-extraction",	
			   "description" : "Don't create nodes for files stored inside compound document",
			   "input": Argument.Empty})
    self.conf.addArgument({"name": "no-text",	
			   "description" : "Don't extract text from word document",
			   "input": Argument.Empty})
    self.conf.addArgument({"name": "no-pictures",	
			   "description" : "Don't extract pictures from word and powerpoint document",
			   "input": Argument.Empty})
    self.conf.addArgument({"name" : "no-root_metadata",
			   "description" : "Don't apply metadata on the root document",
			   "input": Argument.Empty})
    #self.flags = ["single"]
    self.tags = "Metadata"
    self.icon = ":document.png"
