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
#  Solal Jacob <sja@digital-forensic.org>
# 

__dff_module_hash_version__ = "1.0.0"

import hashlib, os

from dff.api.vfs import vfs 
from dff.api.module.script import Script 
from dff.api.module.module import Module 
from dff.api.types.libtypes import Variant, VMap, VList, Parameter, Argument, typeId
from dff.api.vfs.libvfs import AttributesHandler

class HashSets(object):
  KNOWN_GOOD = True
  KNOWN_BAD = False
  def __init__(self):
     self.hsets = []

  def add(self, hsetpath, hsettype):
     for hid in xrange(0, len(self.hsets)):
	hset = self.hsets[hid]
        if hset.path == hsetpath:
	  if hset.knownGood  != hsettype:
	    if hset.knownGood == self.KNOWN_GOOD:
	      print 'Hash set ' + str(hsetpath) + ' was already set as good, keeping old value'
	    else:
	      print 'Hash set ' + str(hsetpath) + ' was already set as bad, keeping old value'
	  return hid
     try:
       self.hsets.append(HashSet(hsetpath, hsettype))
     except RuntimeError:
	raise
     return len(self.hsets) - 1

  def get(self, hsetid):
     return self.hsets[hsetid]

  def find(self, baseIDs, hash_value):
      foundinbase = []
      for baseID in baseIDS:
	 if getBase(baseIds).find(hash_value):
	   foundinbase += baseID
      return foundinbase

class HashSet(object):
  def __init__(self, hash_set, hsettype):
     self.hashType = None
     self.path = hash_set
     self.knownGood = hsettype
     if len(hash_set.split('\\')) != 1:
	self.name = hash_set.split('\\')[-1]
     elif len(hash_set.split('/')) != 1:
	self.name = hash_set.split('/')[-1]
     else:
	 self.name = hash_set
     self.size = os.path.getsize(hash_set)
     self.gettype()

  def algo(self):
     return self.hashType

  def gettype(self):
     f = open(self.path)
     self.headerSize = 0
     self.lineSize = len(f.readline())
     self.hashSize = self.lineSize - 1
     for algo in hashlib.algorithms:
	hobj = getattr(hashlib, algo)
	if (hobj().digestsize * 2) == self.hashSize:
	   self.hashType = algo
	   continue
     if self.hashType == None:
	f.close()
	raise RuntimeError("Hash set " + self.path + " type not found")
     self.len = (self.size - self.headerSize) / self.lineSize
     f.close()

  def getLine(self, file, line):
     file.seek(self.headerSize + (line * self.lineSize), 0)
     return int(file.read(self.hashSize), 16)

  def find(self, h):
     file = open(self.path)
     h = int(h, 16)
     found = self.binSearch(file, h, 0, self.len - 1)
     file.close()
     return found

  def binSearch(self, file, sha, low, high):
     while low <= high:
	mid = (low + high) / 2
	fsha = self.getLine(file, mid)
	if fsha < sha:
	  low = mid + 1
        elif fsha > sha:
	   high = mid - 1
        else: 
	   file.close()
	   return True
     return False

  def __len__(self):
      return self.len


class HashInfo(object):
    def __init__(self):
       self.hashes = {}
       self.hsets = set()

class AttributeHash(AttributesHandler): 
    def __init__(self, parent, modname):
       AttributesHandler.__init__(self, modname)
       self.calculatedHash = {}
       self.parent = parent
       self.__disown__()	

    def haveHash(self, node, algo):
       try:	
	if self.calculatedHash[long(node.this)].has_key(algo):
	  return True
       finally:
	 return False	

    def getHashes(self, node):
       hdic = {}
       calclist = []
       try:
	  hashes = self.calculatedHash[long(node.this)].hashes
	  for h in hashes:
	    if hashes[h] == None:
	      calclist.append(h)
	    else:
	      hdic[h] = hashes[h]
	  if len(calclist):
  	    hinstances = self.parent.calc(node, calclist)
	    for hinstance in hinstances:
	      hdic[hinstance.name] = hinstance.hexdigest()
	  return hdic
       except KeyError:
	  return {}

    def getHash(self, node, algo):
       try :
          h = self.calculatedHash[long(node.this)].hashes[algo]
	  if h == None:
	    return self.parent.calc(node, [algo])[0].hexdigest()
	  return h
       except KeyError:
         return None

    def setHash(self, node, algo, h):
	try:
	  hashInfo = self.calculatedHash[long(node.this)]
	except KeyError:
	    hashInfo = HashInfo()
            self.calculatedHash[long(node.this)] = hashInfo
        hashInfo.hashes[algo] = h
        node.attributesHandlers().updateState()

    def setKnown(self, node, setId):
	try:
	   hashInfo = self.calculatedHash[long(node.this)]
	except KeyError:
	   hashInfo = HashInfo() 
	   self.calculatedHash[long(node.this)] = hashInfo
	hashInfo.hsets.add(setId)
        node.attributesHandlers().updateState()

    def attributes(self, node):
       m = VMap() 
       hinfos = self.calculatedHash[long(node.this)]
       hashes = self.getHashes(node)
       for algo in hashes:
	  v = Variant(str(hashes[algo]))
	  m[str(algo)] = v
       if len(hinfos.hsets):
	 knownBad = []
	 knownGood = []
         for setId in hinfos.hsets:	
	     hset = self.parent.hashSets.get(setId)	    
	     if hset.knownGood:
		knownGood.append(hset)	
	     else:
	 	knownBad.append(hset)
	 if len(knownBad):
	   badList = VList()
	   for badSet in knownBad:
	     vname = Variant(badSet.name)
	     badList.append(vname)
 	   m["known bad"] = badList
	 if len(knownGood):
	   goodList = VList()
	   for goodSet in knownGood:
	     vname = Variant(goodSet.name)
	     goodList.append(vname)
	   m["known good"] = goodList
       return m

    def __del__(self):
	pass

class HASH(Script): 
    def __init__(self):
        Script.__init__(self, "hash")   
        self.vfs = vfs.vfs()
        self.attributeHash = AttributeHash(self, "hash") 
	self.hashSets = HashSets()
        self.knownBadFiles = 0
        self.knownGoodFiles = 0
        self.errorFiles = 0
	self.skippedFiles = 0
        self.setResults() 

    def setResults(self):
        v  = Variant(len(self.attributeHash.calculatedHash))
        self.res["hashed files"] = v
 	v = Variant(self.knownGoodFiles)
       	self.res["known good files"] = v
	v = Variant(self.knownBadFiles)
	self.res["known bad files"] = v
        v = Variant(self.skippedFiles)
	self.res["skipped files"] = v
	v =  Variant(self.errorFiles)
	self.res["Errors"] = v 

    def start(self, args):
	currentSetId = []
	lalgorithms = []
	try:
	  goodBases = args["known_good"].value()
	  for base in goodBases:
	    try:
	      base = self.hashSets.add(base.value().path, HashSets.KNOWN_GOOD)
	      currentSetId.append(base)
	    except RuntimeError as error:
	      print error
	except IndexError:
	  pass
	try:
	  badBases = args["known_bad"].value()
	  for base in badBases:
	    try :
	      base = self.hashSets.add(base.value().path, HashSets.KNOWN_BAD)
	      currentSetId.append(base)
	    except RuntimeError as error:
		print error
	except IndexError:
	  pass
	try:
          algorithms = args["algorithm"].value()
        except IndexError:
	  algorithms = [] 
        node = args["file"].value()
	try:
	   maxSize = args["skip_size"].value() 
 	   if node.size() > maxSize:
	     self.skippedFiles += 1
	     self.setResults()
	     return 
        except IndexError:
	  pass
	try:
	   self.cacheSize = args["low_cache-limit"].value()
	except IndexError:
	   self.cacheSize = 0 
	   pass

        lalgorithms = set()
	for hsetId in currentSetId:
	   algo = self.hashSets.get(hsetId).algo()
	   lalgorithms.add(algo)
	
        for algo in algorithms:
	    algo = algo.value()
            lalgorithms.add(algo)

	if len(lalgorithms) == 0:
	    lalgorithms.add('sha1')

        if  self.hashCalc(node, lalgorithms) == True:
            node.registerAttributes(self.attributeHash)
	    if len(currentSetId):
	      hset = []
	      hsetresults = None
	      hashes = self.attributeHash.getHashes(node)
	      for algo in lalgorithms:
		for hsetid in currentSetId:
		   hset = self.hashSets.get(hsetid)
		   if algo == hset.algo():	
		      if hset.find(hashes[algo]):
		        self.attributeHash.setKnown(node, hsetid) 
			if hset.knownGood:
			  self.knownGoodFiles += 1
			  node.setTag("known good")
			else:
			  self.knownBadFiles += 1
			  node.setTag("known bad")
        self.setResults()

    def hashCalc(self, node, algorithms):
        if node.size() == 0:
	    return False
	doalgo = []
	for algo in algorithms:
	     if not self.attributeHash.haveHash(node, algo):
	       if node.size() > self.cacheSize:
	         doalgo.append(algo)
	       else:
		 self.attributeHash.setHash(node, algo, None)
	if len(doalgo) == 0: 
	   return True 
        hinstances = self.calc(node, doalgo)
	if len(hinstances) == 0:
	   return False
        for hinstance in hinstances:
	   self.attributeHash.setHash(node, hinstance.name, hinstance.hexdigest())
	return True 
 
    def calc(self, node, algorithms):
        buffsize = 10*1024*1024
        hinstances = []
        for algo in algorithms:
            if hasattr(hashlib, algo):
                func = getattr(hashlib, algo)
                instance = func()
                hinstances.append(instance)
        if len(hinstances):
            try :
                f = node.open()
            except IOError as e:
		f.close()
		self.errorFiles += 1
		return []
            buff = f.read(buffsize)
            total = len(buff)
            while len(buff) > 0:
                self.stateinfo = node.name() + " %d" % ((total / float(node.size())) * 100) + "%"
                for hinstance in hinstances:
                    hinstance.update(buff)
                try :
                    buff = f.read(buffsize)
                    total += len(buff)
                except IOError as e:
                    print "Error hashing files " + str(node.absolute()) + " can't read between offsets " + str(total) + " and " + str(total+buffsize)
		    break
                self.stateinfo = node.name() + " %d" % ((total / float(node.size())) * 100) + "%" 
            f.close()
	    return hinstances
	self.errorFiles += 1
        return [] 

    
class hash(Module):
    """Hash a file and add the results in the file attribute.
ex: hash /myfile"""
    def __init__(self):
        Module.__init__(self, "hash", HASH)
        self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node,
                               "name": "file",
                               "description": "file to hash"
                               })
        self.conf.addArgument({"input": Argument.Optional|Argument.List|typeId.String,
                               "name": "algorithm",
                               "description": "algorithm(s) used to hash file",
                               "parameters": {"type": Parameter.NotEditable,
                                              "predefined": ["sha1", "md5", "sha224", "sha256", "sha384", "sha512"]}
                               })
	self.conf.addArgument({"input": Argument.Optional|Argument.List|typeId.Path,
			       "name": "known_good",
			       "description" : "Path to file containing a sets of known good hashes",
			      }) 
 	self.conf.addArgument({"input": Argument.Optional|Argument.List|typeId.Path,
			       "name": "known_bad",
			       "description" : "Path to file containing a sets of known bad hashes",
			      })
        self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.UInt64,
			       "name": "skip_size",
			       "description" : "Each node with a size greater or equal to the one set will node be hashed"}) 
        self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.UInt64,
			       "name": "low_cache-limit",
			       "description" : "Set a low bound size for the cache.\nEach hash of a node with a size lesser or equal to the one set will not be cached,\nthis could lower the RAM usage on a dump with a very huge amount of nodes",
			      })
        self.flags = ["single", "generic"]
        self.tags = "Hash"
        self.icon = ":filehash"
