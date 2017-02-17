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
#  Christophe Malinge <cma@digital-forensic.org>
# 
import sys

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import QTranslator

from dff.ui.conf import Conf

class Translator():
    """ This singleton class handle Qt and DFF translations

    self.dff stores DFF translations
    self.generic stores generic translator from QT
    No need to translate what is already translated. For Ok, Cancel, etc.
    """
    class __Translator():
        def __init__(self):
            self.dff = QTranslator()

            self.generic = QTranslator()
            self.Conf = Conf()
            self.loadLanguage()

        def loadLanguage(self):
            """ Load DFF translation + a Qt translation file

            FIXME need to check if qt4 directory exists in /usr/share or /usr/local/share
            """
            
            l1 = self.generic.load('/usr/share/qt4/translations/qt_' + str(self.Conf.getLanguage()).lower()[:2])
            l2 = self.dff.load(sys.modules['dff.ui.gui'].__path__[0] + "/i18n/Dff_" + str(self.Conf.getLanguage()).lower()[:2])

            return l1 and l2

        def getDFF(self):
            return self.dff
        
        def getGeneric(self):
            return self.generic
        
    __instance = None
    
    def __init__(self):
        if Translator.__instance is None:
            Translator.__instance = Translator.__Translator()
            
    def __setattr__(self, attr, value):
	setattr(self.__instance, attr, value)
  
    def __getattr__(self, attr):
        return getattr(self.__instance, attr)
