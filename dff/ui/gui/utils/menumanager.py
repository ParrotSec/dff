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
#  Jeremy Mounier <jmo@arxsys.fr>
# 
from PyQt4.QtGui import QMenu, QIcon, QWidget, QCursor, QApplication, QAction, QMessageBox, QImage
from PyQt4.QtCore import SIGNAL, SLOT, QObject, QEvent, QString, QBuffer, QByteArray

from dff.api.loader import loader
from dff.api.vfs.libvfs import VFS, ABSOLUTE_ATTR_NAME
from dff.api.types.libtypes import typeId, Variant
from dff.api.taskmanager.taskmanager import TaskManager 
from dff.api.taskmanager.processus import ProcessusManager

from dff.api.gui.dialog.extractor import Extractor

from dff.ui.gui.utils.utils import Utils
from dff.ui.gui.utils.action import newAction, Action
from dff.ui.gui.utils.menu import tagMenu, selectionMenu, BookmarkManager
from dff.ui.gui.resources.ui_nodeactions import Ui_nodeActions

modulePriority = {}

class MenuManager(QWidget, Ui_nodeActions):
  def __init__(self, selection, listmodel):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.processusManager = ProcessusManager()
    self.loader = loader.loader()
    self.lmodules = self.loader.modules
    self.taskmanager = TaskManager()
    self.mainwindow = QApplication.instance().mainWindow
    self.createActions()
    self.checkedSelection = selection
    self.selection = None
    self.model = listmodel
    self.bookManager = BookmarkManager(self.model)

  def createActions(self):
    self.extractor = Extractor(self.mainwindow)
    self.connect(self.extractor, SIGNAL("filled"), self.launchExtract)
    self.actionOpen.setParent(self.mainwindow)
    self.actionOpen_in_new_tab.setParent(self.mainwindow)
    self.connect(self.actionOpen, SIGNAL("triggered()"), self.openDefault)
    self.connect(self.actionOpen_in_new_tab, SIGNAL("triggered()"), self.openAsNewTab)
    self.connect(self.actionOpen_parent_folder, SIGNAL("triggered()"), self.openParentFolder)
    self.connect(self.actionHex_viewer, SIGNAL("triggered()"), self.launchHexedit)
    self.connect(self.actionExtract, SIGNAL("triggered()"), self.extractNodes)
    self.connect(self.actionBookmark, SIGNAL("triggered()"), self.bookmark)

  def createMenu(self):
    nodeclicked = self.model.currentNode()
    self.mainmenu = QMenu(self.mainwindow)
    self.selection = self.model.currentNode()
    self.setOpenRelevant()
    self.setOpenWith()
    self.mainmenu.addAction(self.actionOpen)
    self.mainmenu.addAction(self.actionOpen_with)
    self.mainmenu.addAction(self.actionOpen_in_new_tab)
    self.mainmenu.addAction(self.actionOpen_parent_folder)
    if nodeclicked.isDir() or nodeclicked.hasChildren():
      self.actionOpen_parent_folder.setVisible(False)
      self.actionOpen_parent_folder.setEnabled(False)
      self.actionOpen_in_new_tab.setVisible(True)
      self.actionOpen_in_new_tab.setEnabled(True)
    else:
      self.actionOpen_in_new_tab.setVisible(False)
      self.actionOpen_in_new_tab.setEnabled(False)
      self.actionOpen_parent_folder.setVisible(True)
      self.actionOpen_parent_folder.setEnabled(True)

    self.mainmenu.addSeparator()
    selection = selectionMenu(self, self.model)
    self.mainmenu.addMenu(selection)
    tags = tagMenu(self, self.mainwindow, self.model)
    self.actionTags.setMenu(tags)
    self.mainmenu.addAction(self.actionTags)
    self.mainmenu.addAction(self.actionBookmark)
    self.bookseparator = self.mainmenu.addSeparator()
    self.mainmenu.addAction(self.actionHex_viewer)
    self.mainmenu.addAction(self.actionExtract)

    self.mainmenu.popup(QCursor.pos())
    self.mainmenu.show()

  def setOpenRelevant(self):
    if self.selection != None:
      node = self.selection
      modules = node.compatibleModules()
      if len(modules):
        relevant = QMenu()
        for modname in modules:
          module = self.loader.modules[modname]
          relevant.addAction(newAction(self, self.mainwindow,  modname, module.tags, module.icon))
        self.actionOpen.setMenu(relevant)

  def setOpenWith(self):
    owmenu = QMenu()
    setags = Utils.getSetTags()
    selist = list(setags)
    selist.sort()
    owmenu.addAction(self.mainwindow.actionBrowse_modules)
    owmenu.addSeparator()
    for tags in selist:
      if not tags == "builtins":
        action = QAction(QString(tags), self.mainwindow)
        menu = self.getMenuFromModuleTag(tags)
        action.setMenu(menu)
        owmenu.addAction(action)
    self.actionOpen_with.setMenu(owmenu)

  def getMenuFromModuleTag(self, tagname):
    menu = QMenu()
    modules = self.loader.modules
    for mod in modules :
      m = modules[mod]
      try :
        if m.tags == tagname:
          menu.addAction(newAction(self, self.mainwindow, mod, tagname, m.icon))
#            actions.append(newAction(self, self.__mainWindow, mod, self.tags, m.icon))
      except AttributeError, e:
        pass
    return menu

#####################################
#        CALLBACKS
#####################################
  def selectAll(self):
    self.model.selectAll()

  def openAsNewTab(self):
    node = self.model.currentNode()
    self.mainwindow.addNodeBrowser(node)

  def openParentFolder(self):
    node = self.model.currentNode().parent()
    self.mainwindow.addNodeBrowser(node)

  def launchHexedit(self):
     node = self.model.currentNode()
     conf = self.loader.get_conf("hexadecimal")
     errnodes = ""
#     for node in nodes:
     if node.size():
       try:
         arg = conf.generate({"file": node})
         self.taskmanager.add("hexadecimal", arg, ["thread", "gui"])
       except RuntimeError:
         errnodes += node.absolute() + "\n"
     else:
       errnodes += node.absolute() + "\n"
     if len(errnodes):
       msg = QMessageBox(self)
       msg.setWindowTitle(self.tr("Empty files"))
       msg.setText(self.tr("the following nodes could not be opened with Hex viewer because they are either empty or folders\n"))
       msg.setIcon(QMessageBox.Warning)
       msg.setDetailedText(errnodes)
       msg.setStandardButtons(QMessageBox.Ok)
       ret = msg.exec_()

  def bookmark(self):
     self.bookManager.launch()

  def extractNodes(self):
     if len(self.model.selection.get()) == 0:
       nodes = [self.model.currentNode()]
     else:
       nodes = self.model.selection.getNodes()
     self.extractor.launch(nodes)


  def launchExtract(self):
     args = self.extractor.getArgs()
     conf = self.loader.get_conf("extract")
     try:
       margs = conf.generate(args)
       self.taskmanager.add("extract", margs, ["thread", "gui"])
     except RuntimeError as e:
       msg = QMessageBox(self)
       msg.setWindowTitle(self.tr("Extraction Error"))
       msg.setText(self.tr("An issue occured while extracting \n"))
       msg.setIcon(QMessageBox.Warning)
       msg.setDetailedText(str(e))
       msg.setStandardButtons(QMessageBox.Ok)
       ret = msg.exec_()

  def openDefault(self, node = None):
     if not node:
       node = self.model.currentNode()
     mods = node.compatibleModules()
     if len(mods):
       for mod in mods:
          if "Viewers" in self.lmodules[mod].tags:
	    break
       try:
         priority = modulePriority[mod]
       except KeyError:
         modulePriority[mod] = 0
         priority = 0
       if self.lmodules[mod]:
         conf = self.lmodules[mod].conf
         arguments = conf.arguments()
         marg = {}
         for argument in arguments:
           if argument.type() == typeId.Node:
             marg[argument.name()] = node
         args = conf.generate(marg)
	 if self.processusManager.exist(self.lmodules[mod], args):
	   mbox = QMessageBox(QMessageBox.Warning, self.tr("Module already applied"), self.tr("This module was already applied with the same configuration ! Do you want to apply it again ?"), QMessageBox.Yes | QMessageBox.No, self)
	   reply = mbox.exec_()
	   if reply == QMessageBox.No:
	      return
         else:
          if not priority: 
           mbox = QMessageBox(QMessageBox.Question, self.tr("Apply module"), self.tr("Do you want to apply module ") + str(mod) + self.tr(" on this node ?"), QMessageBox.Yes | QMessageBox.No, self)
           mbox.addButton(self.tr("Always"), QMessageBox.AcceptRole)
	   reply = mbox.exec_() 
           if reply == QMessageBox.No:
             return		
           elif reply == QMessageBox.AcceptRole:
	     modulePriority[mod] = 1 
         self.taskmanager.add(mod, args, ["thread", "gui"])       
	 return
     else:
       errnodes = ""
       if node.size():
         conf = self.lmodules["hexadecimal"].conf
         try:
           arg = conf.generate({"file": node})
           self.taskmanager.add("hexadecimal", arg, ["thread", "gui"])
         except RuntimeError:
           errnodes += node.absolute() + "\n"
       else:
         errnodes += node.absolute() + "\n"
       if len(errnodes):
         msg = QMessageBox(self)
         msg.setWindowTitle(self.tr("Empty files"))
         msg.setText(self.tr("the following nodes could not be opened with Hex viewer because they are either empty or folders\n"))
         msg.setIcon(QMessageBox.Warning)
         msg.setDetailedText(errnodes)
         msg.setStandardButtons(QMessageBox.Ok)
         ret = msg.exec_()


  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.retranslateUi(self)
#      self.mainwindow.changeEvent(event)
#      self.menuModule.setTitle(self.actionOpen_with.text())
#      self.submenuRelevant.setTitle(self.actionRelevant_module.text())
#      self.model.translation()
#      self.treeModel.translation()
    else:
      QWidget.changeEvent(self, event)
