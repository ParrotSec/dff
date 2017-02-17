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
#  Frederic Baguelin <fba@digital-forensic.org>
#  Solal Jacob <sja@digital-forensic.org>

import sys, os, getopt
from distutils.sysconfig import get_python_lib

from dff.api.loader.loader import loader 
from dff.ui.conf import Conf
from dff.ui.redirect import RedirectIO

# ensure dist-packages will be loaded be pyshared on Debian
# else private modules won't be found
if not os.path.exists(os.path.join("dff", "modules")) and os.path.exists(os.path.join(get_python_lib(), "dff")):
    sys.path.insert(0, os.path.join(get_python_lib()))

class UI():
  """This classes manage and let you launch different type of user 
interfaces"""
  def __init__(self, debug = False, verbosity = 0):
   self.debug = debug
   self.verbosity = verbosity
   RedirectIO(None, self.debug)
   self.loader = loader()

  def launch(self, modulesPaths = None):
     print 'This method must be overwritten by an inherited classes'

  def modulesLocalPath(self, modulesPaths):
     modulesLocalPath = []
     for modulesPath in modulesPaths:
        if os.name != "posix":
          modulesPath = modulesPath.replace('/', '\\')
        if os.path.exists(modulesPath):
          modulesLocalPath.append(modulesPath)
        else:
          modulesLocalPath.append(os.path.join(get_python_lib(), modulesPath)) 
     return modulesLocalPath

  def loadModules(self, modulesPaths, displayOutput = None):
     modulesPaths = self.modulesLocalPath(modulesPaths)
     self.loader.do_load(modulesPaths, displayOutput, reload = False)

class Usage():
   PROGRAM_USAGE = """DFF\nDigital Forensic Framework\n
Usage: """ + sys.argv[0] + """ [options]
Options:
  -v      --version                  display current version
  -g      --graphical                launch graphical interface
  -b      --batch=FILENAME	     executes batch contained in FILENAME
  -l      --language=LANG            use LANG as interface language
  -h      --help                     display this help message
  -d      --debug                    redirect IO to system console
          --verbosity=LEVEL          set verbosity level when debugging [0-3]
  -c      --config=FILEPATH          use config file from FILEPATH
"""
   VERSION = "1.3.0"

   def __init__(self, argv):
     self.argv = argv
     self.graphical = 0
     self.test = ''
     self.confPath = ''
     self.debug = False
     self.verbosity = 0
     self.batch = None
# Configuration
     self.main()
     self.conf = Conf(self.confPath)
  

   def main(self):
    """Check command line argument"""
    try:
        opts, args = getopt.getopt(self.argv, "vgdht:l:c:b:", [ "version", "graphical",  "debug", "help", "test=", "language=", "verbosity=", "config=", "batch="])
    except getopt.GetoptError:
        self.usage()
    for opt, arg in opts:
        if opt in ("-h", "--help"):
          self.usage()
        elif opt in ("-g", "--graphical"):
          self.graphical = 1
        elif opt in ("-t", "--test"):
          self.test = arg
        elif opt in ("-l", "--language"):
          self.conf.setLanguage(arg[:2])
        elif opt in ("-v", "--version"):
          print "dff version " + self.VERSION
          sys.exit(1)
        elif opt in ("-d", "--debug"):
          self.debug = True
        elif opt == "--verbosity":
          self.verbosity = int(arg)
        elif opt in ("-c", "--config"):
          self.confPath = str(arg)
	elif opt in  ("-b", "--batch"):
	  self.batch = str(arg)
    return

   def usage(self):
    """Show usage"""
    print self.PROGRAM_USAGE
    sys.exit(2)

