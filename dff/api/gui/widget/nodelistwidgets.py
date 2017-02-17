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
#  Jeremy MOUNIER <jmo@digital-forensic.org>

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *

import re

from dff.api.vfs.vfs import vfs, Node
from dff.api.vfs.libvfs import VFS, VecNode, TagsManager
from dff.api.types.libtypes import typeId, Variant, RCVariant
from dff.api.filters.libfilters import Filter
from dff.api.events.libevents import event, EventHandler

from dff.api.gui.widget.propertytable import PropertyTable
from dff.api.gui.model.node_list import NodeListModel
from dff.api.gui.model.tree import TreeModel
from dff.api.gui.model.selection import SelectionManager
from dff.api.gui.view.tree import NodeTreeView
from dff.api.gui.widget.nodewidget import NodeWidget
from dff.api.gui.widget.search.thread import SearchThread
from dff.api.gui.widget.search.search_widget import SearchPanel
from dff.api.gui.widget.search.filter import FilterBar
from dff.api.gui.dialog.selectattributes import SelectAttributesWizard

from dff.ui.gui.utils.menu import tagMenu, typeFilterMenu, BookmarkManager
from dff.ui.gui.resources.ui_browser_toolbar import Ui_BrowserToolBar
from dff.ui.gui.resources.ui_filter_widget import Ui_filterWidget
from dff.ui.gui.resources.ui_filter_tagwidget import Ui_filterTagwidget

# browser modes
SIMPLE = 0 # No navigation, no filters, no search, no tree
#FILTER = 1 # No navigation, no search, no tree
ADVANCED = 1 # All features
#VIEW PAN
LIST_VIEW = 0
ICON_VIEW = 1
SEARCH_RESULT = 2
FILTER_RESULT = 3
# LEFT PAN
TREE_VIEW = 0
SEARCH_PAN = 1

class NodeListWidgets(Ui_BrowserToolBar, QWidget, EventHandler):
  def __init__(self, parent=None, mode=ADVANCED):
    EventHandler.__init__(self)
    super(QWidget, self).__init__(parent)
    self.setupUi(self)
    self.type = "filebrowser"
    self.icon = None
    self.name = "nodebrowser"
    self.setObjectName(self.name)    
    #Define browser functions
    self.mode = mode
    self.mainwindow = QApplication.instance().mainWindow
    # Main layout
    self.mainlayout = QVBoxLayout()
    self.mainlayout.setSpacing(0)
    self.mainlayout.setMargin(0)

    self.createSelection()
    self.attributes = PropertyTable(self)
    if mode == ADVANCED:
      self.createNavigationHeader()

    self.createToolbar()
    self.createViewPan()
    self.createViews()
    self.setLayout(self.mainlayout)
    self.VFS = VFS.Get()
    self.VFS.connection(self)
    self.connect(self, SIGNAL("refreshList"), self.refreshList)
    self.bookManager = BookmarkManager(self.model())

  def __del__(self):
    self.VFS.deconnection(self)
    self.treemodel.VFS.deconnection(self.treemodel)

  def Event(self, e):
    """
    Add e.value, which is a Variant containing a Node, in the tree (only if it has children
    or is a directory).
    """
    self.emit(SIGNAL("refreshList"), e)

  def refreshList(self, e):
    if e.value != None:
      if self.mode == ADVANCED:
        node = e.value.value()
        if node == None or self.navigation.currentNode == None:
          return
        try:
          parent = node.parent()
          navnode = self.navigation.currentNode
        # XXX Identify event type (add node or apply module)
          if navnode.absolute() == parent.absolute():
            child = parent.children()
          elif navnode.absolute() == parent.parent().absolute():
            child = parent.parent().children()
          else:
            return
          self.currentView().model.changeList(child)
          self.currentView().refreshVisible()
        except:
          pass

  def createSelection(self):
    self.selection = SelectionManager()
    self.connect(self.selection, SIGNAL("selectionChanged()"), self.refreshModels)

  def createNavigationHeader(self):
    self.header = QSplitter(Qt.Horizontal)
    self.navigation = NavigationBar(self)
    self.navigationtoolbar = self.navigation.getPathbar()
    self.header.addWidget(self.navigationtoolbar)
    self.header.setStretchFactor(0, 60)
    self.mainlayout.addWidget(self.header, 0)

  def createToolbar(self):
    self.toolbar = QToolBar()
    self.toolbar.setMaximumHeight(32)
    self.toolbar.addAction(self.actionFactorMinus)
    self.connect(self.factorSlider, SIGNAL("valueChanged(int)"), self.refreshIconSize)
    self.toolbar.addWidget(self.factorSlider)
    self.toolbar.addAction(self.actionFactorPlus)

    self.connect(self.actionFactorMinus, SIGNAL("triggered()"), self.factorminus)
    self.connect(self.actionFactorPlus, SIGNAL("triggered()"), self.factorplus)

    self.toolbar.addWidget(self.changeView)
    self.connect(self.changeView, SIGNAL("currentIndexChanged(int)"), self.viewChanged)
    self.toolbar.addAction(self.actionAttributes)
    self.connect(self.actionAttributes, SIGNAL("triggered()"), self.selectAttributes)
    self.toolbar.addAction(self.actionBookmark)
    self.connect(self.actionBookmark, SIGNAL("triggered()"), self.bookmark)
 
    menutag = tagMenu(self, self.mainwindow)
    self.tags.setMenu(menutag)
    self.toolbar.addWidget(self.tags)

    if self.mode == ADVANCED:
      self.toolbar.addWidget(self.search)
      self.connect(self.search, SIGNAL("clicked(bool)"), self.activateSearchPan)
    else:
      self.search.setVisible(False)
    self.toolbar.addWidget(self.filter)
    self.connect(self.filter, SIGNAL("clicked(bool)"), self.viewFilter)
    self.mainlayout.addWidget(self.toolbar, 0)

  def viewFilter(self):
    if self.filter.isChecked():
      self.infostack.setCurrentWidget(self.filterwidget)
      self.viewpan.setCurrentWidget(self.filterview)
      self.filterwidget.resetFilter()
      m = self.currentView().model
#      if self.filter.isChecked():
      self.filterview.model.setDefaultAttributes()
      self.filterview.model.setSelectedAttributes(m.selectedAttributes())
      self.infostack.show()
    else:
      self.infostack.setCurrentWidget(self.filterwidget)
      self.viewpan.setCurrentWidget(self.currentView())
      self.infostack.hide()

  def factorminus(self):
    value = self.factorSlider.value() - 1
    if value >= 1:
      self.factorSlider.setValue(value)
      self.refreshIconSize(value)

  def factorplus(self):
    value = self.factorSlider.value() + 1
    if value <= 4:
      self.factorSlider.setValue(value)
      self.refreshIconSize(value)

  def refreshIconSize(self, value):
    for view in self.views:
      view.refreshIconSize(value)

  def createViewPan(self):
    self.viewstack = QWidget()
    self.viewlayout = QVBoxLayout()
    self.viewlayout.setSpacing(0)
    self.viewlayout.setMargin(0)
    self.viewpan = QStackedWidget()
    self.infostack = QStackedWidget()
    self.filterwidget = FilterWidget(self)
    self.infostack.addWidget(self.filterwidget)
    self.infostack.hide()
    self.viewlayout.addWidget(self.infostack, 0)
    self.viewlayout.addWidget(self.viewpan, 90)
    self.viewstack.setLayout(self.viewlayout)

  def createNodeWidget(self, selection, tabmode=False, filtermode=False):
     return NodeWidget(selection, tabmode, filtermode)

  def createViews(self):
    self.views = []
    self.splitter = QSplitter(self)
    self.browserview = self.createNodeWidget(self.selection)
    self.connect(self.browserview, SIGNAL("nodePressed"), self.nodePressed)
    # append
    self.views.append(self.browserview)
    self.viewpan.addWidget(self.browserview)
    self.leftpan = QStackedWidget()
    if self.mode == ADVANCED:
      # Tree view
      self.treeview = NodeTreeView(self)
      self.treemodel = TreeModel(self, self.selection)
      self.treeview.setModel(self.treemodel)
      self.leftpan.addWidget(self.treeview)
      self.connect(self.treeview, SIGNAL("nodeTreeClicked"), self.nodetreeclicked)
      self.navigation.connect(self.browserview, SIGNAL("pathChanged"), self.navigation.rootpathchanged)
      self.navigation.connect(self.treeview, SIGNAL("nodeTreeClicked"), self.navigation.pathChanged)
      # Search view
    self.searchview = self.createNodeWidget(self.selection,tabmode=True)
    self.connect(self.searchview, SIGNAL("nodePressed"), self.nodePressed)
    self.views.append(self.searchview)
    self.viewpan.addWidget(self.searchview)
    # Filter view
    self.filterview = self.createNodeWidget(self.selection, filtermode=True)
    self.connect(self.filterview, SIGNAL("enterFilter"), self.enterFilter)
    self.connect(self.filterview, SIGNAL("nodePressed"), self.nodePressed)
    if self.mode == ADVANCED:
      self.navigation.connect(self.filterview, SIGNAL("pathChanged"), self.navigation.rootpathchanged)
    self.views.append(self.filterview)
    self.viewpan.addWidget(self.filterview)
    if self.mode == ADVANCED:
      self.searchwidget = SearchPanel(self, self.searchview)
      self.leftpan.addWidget(self.searchwidget)
    self.splitter.addWidget(self.leftpan)
    self.splitter.addWidget(self.viewstack)
    self.splitter.addWidget(self.attributes)
    self.splitter.setStretchFactor(0, 25)
    self.splitter.setStretchFactor(1, 60)
    self.splitter.setStretchFactor(2, 15)

    self.mainlayout.addWidget(self.splitter, 50)

  def nodePressed(self, node):
    self.attributes.fill(node)
    self.mainwindow.emit(SIGNAL("previewUpdate"), node)

  def enterFilter(self, node):
    if self.filterwidget.lock.isChecked():
      self.browserview.enterDirectory(node)
      self.filterwidget.quickFilter()
    else:
      self.browserview.enterDirectory(node)
      self.filterwidget.resetFilter()

  def refreshModels(self):
    self.model().emit(SIGNAL("layoutChanged()"))
    if self.mode == ADVANCED:
      self.treemodel.emit(SIGNAL("layoutChanged()"))

  def activateSearchPan(self, state):
    if self.mode == ADVANCED:
      if state:
        self.leftpan.setCurrentIndex(SEARCH_PAN)
        self.navigationtoolbar.setEnabled(False)
        if not self.filter.isChecked():
          self.viewpan.setCurrentWidget(self.searchview)
        else:
          self.viewpan.setCurrentWidget(self.filterview)
      else:
        self.leftpan.setCurrentIndex(TREE_VIEW)
        self.navigationtoolbar.setEnabled(True)
        if not self.filter.isChecked():
          self.viewpan.setCurrentWidget(self.browserview)
        else:
          self.viewpan.setCurrentWidget(self.filterview)
        self.model().refresh(self.model().currentRow())
    else:
      if state:
        self.searchwidget = SearchPanel(self, self.searchview)
        self.leftpan.addWidget(self.searchwidget)
        self.leftpan.setCurrentWidget(self.searchwidget)
        if not self.filter.isChecked():
          self.viewpan.setCurrentWidget(self.searchview)
        else:
          self.viewpan.setCurrentWidget(self.filterview)
        self.leftpan.show()
      else:
        self.leftpan.removeWidget(self.searchwidget)
        self.model().refresh(self.model().currentRow())
        if not self.filter.isChecked():
          self.viewpan.setCurrentWidget(self.browserview)
        else:
          self.viewpan.setCurrentWidget(self.filterview)
        self.leftpan.hide()
    self.filterwidget.resetFilter()

  def applyFilter(self):
    if self.filter.isChecked(): 
      if self.filterwidget.lock.isChecked():
        self.filterwidget.quickFilter()
      else:
        self.filterwidget.resetFilter()

  def nodetreeclicked(self, node, button, rec=False):
    QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
    if not rec:
      self.currentView().model.emit(SIGNAL("changeList"), node.children())
    else:
      res = []
      self.recurseNodes(node, res)
      res.remove(node)
      self.currentView().model.emit(SIGNAL("changeList"), res)
    self.currentView().model.refresh(self.model().currentRow())
    self.currentView().refreshVisible()
    self.applyFilter()
    QApplication.restoreOverrideCursor()

  def recurseNodes(self, node, res):
    res.append(node)
    if node.hasChildren():
       childs = node.children()
       for child in childs:
	  self.recurseNodes(child, res)

  def viewChanged(self, index):
    curentview = self.viewpan.currentWidget()
    curentview.emit(SIGNAL("changeView"), index)

  def selectAttributes(self):
    model = self.currentView().model
    attr = model.availableAttributes()
    wiz = SelectAttributesWizard(self.currentView().model, model.selectedAttributes(), model.defaultAttributes())
    iret = wiz.exec_()
    if iret == 1:
      selected = wiz.getSelectedAttributes()
      model.setSelectedAttributes(selected)
      if self.filter.isChecked():
        self.filterview.model.setSelectedAttributes(selected)


  def bookmark(self):
    self.bookManager.launch()

  def currentView(self):
    if not self.search.isChecked():
      return self.browserview
    else:
      return self.searchview

  def views(self):
    views = []
    views.append(self.browser)
    views.append(self.search)


  def models(self):
    model_list = []
    model_list.append(self.browser.model)
    model_list.append(self.search.model)
    return model_list

  def model(self):
    return self.viewpan.currentWidget().model

  def changeList(self, nodelist):
    self.browserview.model.emit(SIGNAL("changeList"), nodelist)


########################################
#  NAVIGATION
########################################

class FilterWidget(Ui_filterWidget, QWidget):
  def __init__(self, parent):
    QWidget.__init__(self, parent)
    self.setupUi(self)
    self.parent = parent
    self.edit = self.filterCombo.lineEdit()    
    self.filterMode = {0: "$",
                       1: "~",
                       2: "/",
                       3: "\""}
    self.query = ""
    self.createFilterThread()
    self.connect(self.filterTH, SIGNAL("match"), self.updateMatchedNodes)
    self.connect(self.filterTH, SIGNAL("finished"), self.searchStoped)
    self.connect(self.filterTH, SIGNAL("started"), self.searchStarted)
    self.connect(self.filterTH, SIGNAL("stoped"), self.searchStoped)
    self.connect(self.clear, SIGNAL("clicked(bool)"), self.resetFilter)
    self.connect(self.stop, SIGNAL("clicked(bool)"), self.stopFilter)
    self.connect(self.edit, SIGNAL("textChanged(QString)"), self.updateQuery)
    self.connect(self.mode, SIGNAL("currentIndexChanged(int)"), self.modeChanged)
    self.redstyle = QString("QWidget {color:red}")
    self.greenstyle = QString("QWidget {color:green}")
    self.blackstyle = QString("QWidget {color:black}")
    self.matched = 0
    self.stop.setEnabled(False)
    self.timer = QTimer(self)
    self.timer.setSingleShot(True)
    self.filtertagwidget = FilterTagWidget(self)
    self.filtertagwidget.hide()
    self.connect(self.timer, SIGNAL("timeout()"), self.quickFilter)

  def createFilterThread(self):
    self.filterTH = SearchThread(self)

  def updateQuery(self, query):
    self.timer.start(1000)
    if self.mode.currentIndex() in xrange(0,4):
      self.query = query
    else:
      f = Filter("completer")
      try:
        q = str(unicode(query).encode('utf-8'))
        f.compile(q)
        self.edit.setStyleSheet(self.greenstyle)
      except RuntimeError:
        self.edit.setStyleSheet(self.redstyle)

  def modeChanged(self, index):
    if index == 5:
      self.verticalLayout.addWidget(self.filtertagwidget)
      self.filtertagwidget.toolbar.refreshTags()
      self.filterCombo.setEnabled(False)
      self.filtertagwidget.show()
    else:
      self.verticalLayout.removeWidget(self.filtertagwidget)
      self.filterCombo.setEnabled(True)
      self.filtertagwidget.hide()
      

  def launchFilter(self, query=None):
    if not query:
      query = self.filterCombo.lineEdit().text()
    else:
      query = query
    nodelist = self.sourceModel().list()
    if len(nodelist) > 0:
      self.parent.filterview.model.clearList()
      q = str(unicode(query).encode('utf-8'))
      r = self.filterTH.setListContext(q, nodelist, self.parent.filterview.model)
      if r:
        self.filterTH.start()

  def quickFilter(self):
    self.timer.stop()
    index = self.mode.currentIndex()
    if index in xrange(0,4):
      self.filterTH.stopSearch()
      if self.query == "":
        self.resetFilter()
      else:
        self.resetFilter()
        q = "name matches " + self.filterMode[index] + self.query + self.filterMode[index]
        self.launchFilter(q)
    else:
      try:
        query = self.filterCombo.lineEdit().text()
        if query != "":
          f = Filter("test")
          q = str(unicode(query).encode('utf-8'))
          f.compile(q)
          self.edit.setStyleSheet(self.greenstyle)
          self.resetFilter()
          self.launchFilter()
        else:
          self.resetFilter()
      except RuntimeError:
        self.edit.setStyleSheet(self.redstyle)

  def stopFilter(self):
    self.filterTH.stopSearch

  def sourceModel(self):
    if self.parent.search.isChecked():
      return self.parent.searchview.model
    else:
      return self.parent.browserview.model

  def resetFilter(self):
    self.edit.setStyleSheet(self.blackstyle)
    self.parent.filterview.model.changeList(self.sourceModel().list())
    count = len(self.sourceModel().list())
    if count > 0:
      self.reslabel.setStyleSheet(self.greenstyle)
      self.countlabel.setStyleSheet(self.greenstyle)
    else:
      self.reslabel.setStyleSheet(self.redstyle)
      self.countlabel.setStyleSheet(self.redstyle)
    self.countlabel.setText(str(count))
    self.reslabel.setText(str(count))
    self.parent.filterview.refreshVisible()

  def updateMatchedNodes(self):
    if self.matched == 0:
      self.reslabel.setStyleSheet(self.greenstyle)
      self.countlabel.setStyleSheet(self.greenstyle)
    self.matched += 1
    self.countlabel.setText(str(self.matched))
    self.parent.filterview.refreshVisible()

  def searchStoped(self):
    QApplication.restoreOverrideCursor()
    self.stop.setEnabled(False)

  def searchStarted(self):
    QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
    self.stop.setEnabled(True)
    self.matched = 0
    self.reslabel.setStyleSheet(self.redstyle)
    self.countlabel.setStyleSheet(self.redstyle)
    self.countlabel.setText(str(self.matched))
    self.reslabel.show()
    self.countlabel.show()

class FilterTagWidget(Ui_filterTagwidget, QWidget):
  def __init__(self, filterw):
    QWidget.__init__(self, filterw)
    self.setupUi(self)
    self.filterw = filterw
    self.toolbar = TagToolbar(self)
    self.horizontalLayout.addWidget(self.toolbar, 100)

class TagToolbar(QToolBar):
  def __init__(self, parent):
    QToolBar.__init__(self)
    self.filtertw = parent
    self.filterw = parent.filterw
    self.tagsmanager = TagsManager.get()
    self.tagbuttons = []
    self.refreshTags()

  def refreshTags(self):
    self.clear()
    tags = self.tagsmanager.tags()
    for tag in tags:
      t = TagAction(self, tag)
      self.addWidget(t)
      self.tagbuttons.append(t)

  def refreshQuery(self):
    # Count checked :
    count = 0
    for tagb in self.tagbuttons:
      if tagb.isChecked():
        count += 1
    # Build Query
    if count > 0:
      if self.filtertw.exclude.isChecked():
        q = "not tags in ["
      else:
        q = "tags in ["
      check = 0
      for tagb in self.tagbuttons:
        if tagb.isChecked():
          q += "\"" + str(unicode(tagb.text()).encode('utf-8')) + "\""
          if check < count -1:
            q += ","
            check += 1
      q += "]"
      self.filterw.filterCombo.lineEdit().clear()
      self.filterw.filterCombo.lineEdit().setText(QString(q))
    else:
      q = ""
      self.filterw.filterCombo.lineEdit().clear()
    self.filterw.quickFilter()

class TagAction(QToolButton):
  def __init__(self, toolbar, tag):
    QToolButton.__init__(self)
    self.tag = tag
    self.toolbar = toolbar
    self.setCheckable(True)
    self.createStyle()
    self.connect(self, SIGNAL("clicked()"), self.toolbar.refreshQuery)
    self.setText(QString.fromUtf8(self.tag.name()))

  def createStyle(self):
    color = self.tag.color()
    s = "QToolButton {color: rgb(" + str(color.r) + "," + str(color.g) + "," + str(color.b) + ")}"
    self.setStyleSheet(QString(s))

class ToolButtonBar(QToolBar):
  def __init__(self, parent):
    QToolBar.__init__(self)
    self.navigation = parent
    self.setIconSize(QSize(16,16))
    self.createStyle()
    self.setStyleSheet(self.mainstyle)

    sizepolicy = QSizePolicy()
    sizepolicy.setHorizontalStretch(50)
    sizepolicy.setHorizontalPolicy(QSizePolicy.Expanding)
    self.setSizePolicy(sizepolicy)
    self.linedit = QLineEdit()

  def createStyle(self):
    self.mainstyle = "QToolBar {background: #eeeeee;spacing: 3px; border: 1px solid grey; border-radius: 2px;}"
    self.hoverstyle = "QToolBar {background: white;spacing: 3px; border: 1px solid grey; border-radius: 2px;}"
#    self.teststyle = "QToolBar {background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: 0 #ffffff, stop: 1 #000000);}"

  def mousePressEvent(self, event):
    self.navigation.navbars.setCurrentIndex(1)

  def enterEvent(self, event):
    self.setStyleSheet(self.hoverstyle)

  def leaveEvent(self, event):
    self.setStyleSheet(self.mainstyle)

class ToolEditBar(QLineEdit):
  def __init__(self, parent):
    QLineEdit.__init__(self)
    self.navigation = parent
    self.vfs = vfs()
    QObject.connect(self, SIGNAL("textEdited(const QString &)"), self.updatePath)
    self.connect(self, SIGNAL("editingFinished()"), self.focusOut)

  def updatePath(self, path):
    path = unicode(path).encode('utf-8')
    spath = path.split("/")
    spath.pop(0)
    node = self.vfs.getnode("/")
    for nodename in spath:
      if node != None:
        tmpnode = self.getChild(node, nodename)
        if tmpnode == None:
          complete = self.filter(nodename, node)
          if len(complete) > 0:
            menu = Completer(self)
            for count, comp in enumerate(complete):
              item = QAction(self)
              item.setText(QString.fromUtf8(comp.name()))
              item.setIcon(QIcon(":folder.png"))
              item.setData(comp.absolute())
              if count == 0:
                menu.setDefaultAction(item)
              menu.addAction(item)
            menu.setFixedWidth(self.width())
            menu.popup(self.mapToGlobal(QPoint(0,self.height())))
        else:
          node = tmpnode

  def getChild(self, parent, childname):
    children = parent.children()
    for child in children:
      if parent.absolute() != "/":
        if child.isDir() or child.hasChildren():
          if child.name() == childname:
            return child
      else:
        if child.name() == childname:
          return child
    return None

  def filter(self, pattern, node):
    children = self.getDirectories(node)
    if len(children) > 0:
      f = Filter("completer")
      exp = '(name matches re("^'+ pattern +'",i))'
      f.compile(exp)
      f.process(children)
      possible = f.matchedNodes()
      return possible
    return []

  def signalRouter(self, action):
    self.emit(SIGNAL("changeDirectory"), action)

  def getDirectories(self, node):
    res = VecNode()
    if node.absolute() != "/":
      children = node.children()
      for child in children:
        if child.isDir() or child.hasChildren():
          res.append(child)
    else:
      res = node.children()

    return res
                    
  def focusOut(self):
    self.navigation.navbars.setCurrentIndex(0)

class Completer(QMenu):
  def __init__(self, linedit):
    QMenu.__init__(self, linedit)
    self.linedit = linedit
    
    self.connect(self, SIGNAL("triggered(QAction*)"), self.resetLineEdit)
    self.connect(self, SIGNAL("hovered(QAction*)"), self.resetLineEdit)

  def keyPressEvent(self, event):
    actions = self.actions()
    active = self.activeAction()
    try:
      idaction = actions.index(active)
    except:
      idaction = -1
    if event.matches(QKeySequence.MoveToPreviousLine):
      if idaction > 0:
        idaction = idaction - 1
      else:
        idaction = 0
      self.setActiveAction(actions[idaction])
      self.resetLineEdit(actions[idaction])
    elif event.matches(QKeySequence.MoveToNextLine):
      if idaction < len(actions) - 1:
        self.setActiveAction(actions[idaction + 1])
        self.resetLineEdit(actions[idaction + 1])
    elif event.matches(QKeySequence.InsertParagraphSeparator):
      if idaction >= 0:
        self.resetLineEdit(actions[idaction], True)
        self.hide()
      else:
        QLineEdit.keyPressEvent(self.linedit, event)
    else:
      self.hide()
      QLineEdit.keyPressEvent(self.linedit, event)

  def resetLineEdit(self, action, route=False):
    self.linedit.clear()
    self.linedit.setText(QString.fromUtf8(action.data().toString()))
    if route:
      self.linedit.signalRouter(action)

class NavigationBar(QWidget):
  def __init__(self, parent):
    QWidget.__init__(self)
    self.parent = parent
    self.vfs = vfs()
    self.history = ["/"]
    self.currentPathId = -1
    self.currentNode = self.vfs.getnode("/")
    # Create navigation buttons
    self.maintoolbar = QToolBar(self)
    self.maintoolbar.setIconSize(QSize(24,24))
    self.setPreviousButton()
    self.setNextButton()
    self.setTopButton()
    self.setHomeButton()

    self.pathbar = ToolButtonBar(self)
    self.editbar = ToolEditBar(self)

    self.navbars = QStackedWidget()
    self.navbars.setMaximumHeight(25)
    self.navbars.addWidget(self.pathbar)
    self.navbars.addWidget(self.editbar)

    self.maintoolbar.addWidget(self.navbars)

    self.connect(self.editbar, SIGNAL("changeDirectory"), self.pathbarchanged)
    self.connect(self.pathbar, SIGNAL("actionTriggered(QAction*)"), self.pathbarchanged)

  def mousePressEvent(self, event):
    self.navbars.setCurrentIndex(0)

  def setHomeButton(self):
    self.historymenu = QMenu()
    self.homebutton = QToolButton()
    self.homebutton.setIcon(QIcon(":home.png"))
    self.homebutton.setMenu(self.historymenu)
    self.homebutton.setPopupMode(QToolButton.MenuButtonPopup)
    self.maintoolbar.addWidget(self.homebutton)

    self.connect(self.homebutton, SIGNAL("clicked()"), self.goHome)
    self.connect(self.historymenu, SIGNAL("triggered(QAction*)"), self.menuTriggered)

  def setPreviousButton(self):
    self.prevbutton = QToolButton()
    self.prevbutton.setIcon(QIcon(":previous.png"))
    self.prevbutton.setDisabled(True)
    self.maintoolbar.addWidget(self.prevbutton)

    self.connect(self.prevbutton, SIGNAL("pressed()"), self.moveToPrevious)

  def setNextButton(self):
    self.nextbutton = QToolButton()
    self.nextbutton.setIcon(QIcon(":next.png"))
    self.nextbutton.setDisabled(True)
    self.maintoolbar.addWidget(self.nextbutton)
    self.connect(self.nextbutton, SIGNAL("pressed()"), self.moveToNext)

  def setTopButton(self):
    self.topbutton = QToolButton()
    self.topbutton.setIcon(QIcon(":top.png"))
    self.topbutton.setDisabled(True)
    self.maintoolbar.addWidget(self.topbutton)
    self.connect(self.topbutton, SIGNAL("pressed()"), self.moveToTop)

  def setHistoryMenu(self):
    self.historymenu.clear()
    for path in self.history:
      p = QString.fromUtf8(path)
      self.historymenu.addAction(p)

  def menuTriggered(self, action):
    path = action.text().toUtf8()
    path = unicode(path, 'UTF-8').encode("UTF-8")
    node = self.vfs.getnode(path)
    if node:
      self.refreshNode(node)

  def pathInHistory(self, path, hlist):
    for p in hlist:
      if p == path:
        return True
    return False

  def goHome(self):
    home = self.vfs.getnode("/")
    if home != None:
      self.refreshNode(home)

  def moveToTop(self):
    if self.currentNode != None:
      self.refreshNode(self.currentNode.parent())

  def moveToPrevious(self):
    if self.currentPathId > 0:
      self.currentPathId = self.currentPathId - 1
      path = self.history[self.currentPathId]
      node = self.vfs.getnode(path)
      self.refreshNode(node)

  def moveToNext(self):
    if self.currentPathId < len(self.history) - 1:
      self.currentPathId = self.currentPathId + 1
      path = self.history[self.currentPathId]
      node = self.vfs.getnode(path)
      self.refreshNode(node)

  def refreshNode(self, node):
    if node != None:
      self.parent.changeList(node.children())
      self.currentNode = node
      self.changeNavigationState()
      self.parent.treeview.expandToNode(self.currentNode)
      self.parent.viewpan.currentWidget().refreshVisible()
      self.history.append(str(node.absolute()))
      self.parent.applyFilter()

  def pathChanged(self, node):
    try:
      path = node.absolute()
      if len(self.history) > 0:
        if not self.pathInHistory(path, self.history):
          self.history.append(str(node.absolute()))
        self.currentPathId = len(self.history) - 1
        self.currentNode = node
        self.parent.browserview.refreshVisible()
        self.changeNavigationState()
        return True
      return True
    except:
      return False

  def rootpathchanged(self, node, button=None):
    self.pathChanged(node)
    self.parent.treeview.expandToNode(node)

  def changeNavigationState(self):
    if self.currentNode:
      if self.currentNode.absolute() != "/":
        self.topbutton.setEnabled(True)
      else:
        self.topbutton.setEnabled(False)
      self.editbar.clear()
      self.editbar.setText(QString.fromUtf8(self.currentNode.absolute()))
    self.setHistoryMenu()
    if self.currentPathId > 0:
      self.prevbutton.setEnabled(True)
    else:
      self.prevbutton.setEnabled(False)
    if self.currentPathId < len(self.history) -1:
      self.nextbutton.setEnabled(True)
    else:
      self.nextbutton.setEnabled(False)
    self.refreshPathbar()

  def getPathbar(self):
    return self.maintoolbar

  def pathbarchanged(self, action):
    path = action.data().toByteArray()
    path = unicode(path, 'UTF-8').encode("UTF-8")
    node = self.vfs.getnode(path)
    if node:
      self.refreshNode(node)

  def refreshPathbar(self):
    if self.currentNode:
      spath = self.currentNode.absolute().split('/')[1:]
      actions = []
      for count, path in enumerate(spath):
        if path:
          a = QAction(self)
          a.setText(QString.fromUtf8(path))
          abspath = "/" + "/".join(spath[:count + 1])
          a.setData(abspath)
          if count == 0:
            self.setIcon(a, path)
          actions.append(a)
      self.pathbar.clear()
      if len(actions) > 0:
        for act in actions:
          self.pathbar.addAction(act)
        font = QFont()
        font.setItalic(True)
        font.setBold(True)
        act.setFont(font)

  def setIcon(self, action, path):
    if path == "Logical files":
      action.setIcon(QIcon(":folder.png"))
    elif path == "Local devices":
      action.setIcon(QIcon(":dev_hd.png"))
    elif path == "Bookmarks":
      action.setIcon(QIcon(":bookmark.png"))
