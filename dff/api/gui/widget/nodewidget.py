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

from dff.api.vfs.libvfs import VFS

from dff.api.gui.view.node_list import NodeListView
from dff.api.gui.view.node_table import NodeTableView
from dff.api.gui.model.node_list import NodeListModel

from dff.ui.gui.utils.menumanager import MenuManager
from dff.ui.gui.resources.ui_filter_mode import Ui_filterMode

TABLEVIEW_ID = 0
LISTVIEW_ID = 1

class NodeWidget(QWidget):
    """
    This Widget provide a list model with various view
    """
    def __init__(self, selectionManager, tabmode=False, filtermode=False):
        QWidget.__init__(self)
        self.tabmode = tabmode
        self.filtermode = filtermode
        # setup model and views
        self.viewid = TABLEVIEW_ID
        self.model = NodeListModel(selection=selectionManager)
        self.tableview = NodeTableView(self)
        self.listview = NodeListView(self)
        self.tableview.setModel(self.model)
        self.tableview.setColumnWidth(0, 180)
        self.listview.setModel(self.model)
        # Keep track of model list in case of filtering
        self.initialist = []
        # setup graphic stuff
        self.createMainLayout()
        self.createViewLayout()
        self.createStack()
        self.createScrollbar()
        self.createConnections()
        self.menuManager(selectionManager)
        self.connect(self.model, SIGNAL("dataChanged"), self.dataChanged)

    def menuManager(self, selectionManager):
        self.menumanager = MenuManager(selectionManager, self.model)

    def refreshIconSize(self, factor):
        self.tableview.factor = factor
        self.tableview.configure()
        self.listview.factor = factor
        self.listview.configure()
        self.refreshVisible()

    def dataChanged(self, x, y):
        self.viewstack.currentWidget().dataChanged(x, y)

    def createMainLayout(self):
        self.vlayout = QVBoxLayout(self)
        self.vlayout.setSpacing(0)
        self.vlayout.setMargin(0)
        
    def createViewLayout(self):
        container = QWidget()
        self.hlayout = QHBoxLayout()
        self.hlayout.setSpacing(0)
        self.hlayout.setMargin(0)
        container.setLayout(self.hlayout)
        self.vlayout.addWidget(container)

    def createStack(self):
        self.viewstack = QStackedWidget()
        self.viewstack.addWidget(self.tableview)
        self.viewstack.addWidget(self.listview)
        self.hlayout.addWidget(self.viewstack, 99)

    def createScrollbar(self):
        self.scrollbar = ScrollBar(self)
        self.hlayout.addWidget(self.scrollbar, 1)
        self.scrollbar.lower()

    def refreshVisible(self):
        view = self.viewstack.currentWidget()
        view.refreshVisible()

    def createConnections(self):
        self.connect(self, SIGNAL("changeView"), self.changeView)
        self.connect(self.tableview, SIGNAL("nodeListClicked"), self.nodelistclicked)
        self.connect(self.tableview, SIGNAL("nodeListDoubleClicked"), self.nodelistDoubleclicked)
        self.connect(self.model, SIGNAL("nodeListClicked"), self.nodelistclicked)
        self.connect(self.tableview, SIGNAL("enterDirectory"), self.enterDirectory)
        self.connect(self.listview, SIGNAL("enterDirectory"), self.enterDirectory)
        self.connect(self.listview, SIGNAL("nodeListClicked"), self.nodelistclicked)
        self.connect(self.listview, SIGNAL("nodeListDoubleClicked"), self.nodelistDoubleclicked)
        self.connect(self.model, SIGNAL("nodeAppended"), self.refreshVisible)

    def enterDirectory(self, sourcenode):
        if sourcenode != None:
            if (not self.tabmode) and (not self.filtermode):
                self.model.emit(SIGNAL("changeList"), sourcenode.children())
                self.emit(SIGNAL("pathChanged"), sourcenode)
                if len(self.model.list()) > 0:
                    self.nodelistclicked(0)
            if self.filtermode:
                self.emit(SIGNAL("enterFilter"), sourcenode)
            if self.tabmode:
                self.openAsNewTab(sourcenode)
                
        self.refreshVisible()

    def nodelistclicked(self, button):
        if button == Qt.RightButton:
            self.menumanager.createMenu()
        else:
            node = self.model.currentNode()
            self.emit(SIGNAL("nodePressed"), node)

    def nodelistDoubleclicked(self, node):
        self.menumanager.openDefault(node)

    def changeView(self, index):
        self.viewid = index
        if index == TABLEVIEW_ID:
            self.viewstack.setCurrentWidget(self.tableview)
            self.model.refresh(self.model.currentRow())
            self.scrollbar.setMaximum(self.scrollbar.value() - 2)
        elif index == LISTVIEW_ID:
            self.viewstack.setCurrentWidget(self.listview)
            self.model.refresh(self.model.currentRow())
            self.scrollbar.setMaximum(self.scrollbar.value() + 2)
        self.refreshVisible()

    def openAsNewTab(self, rootnode):
        QApplication.instance().mainWindow.addNodeBrowser(rootpath=rootnode)

class ScrollBar(QScrollBar):
    def __init__(self, nodeview):
        QScrollBar.__init__(self, nodeview)
        self.model = nodeview.model
        self.nodeview = nodeview
        self.setMinimum(0)
        self.setMaximum(0)
        self.setVisible(False)
        self.connect(self, SIGNAL("sliderMoved(int)"), self.moveTo)
        self.connect(self, SIGNAL("actionTriggered(int)"), self.triggered)
        # Model signals
        self.connect(self.model, SIGNAL("maximum"), self.updateMaximum)
        self.connect(self.model, SIGNAL("hideScroll"), self.hideScrollbar)
        self.connect(self.model, SIGNAL("current"), self.updateCurrent)
        self.nodeview.hlayout.addWidget(self, 1)
 

    def hideScrollbar(self):
        self.setMinimum(0)
        self.setMaximum(0)
        self.setVisible(False)

    def updateMaximum(self, stop):
        if stop <= self.model.visibleRows():
           self.setMinimum(0)
           self.setMaximum(0)
           self.setVisible(False)
        else:
            m = stop - self.model.visibleRows()
            self.setMaximum(m)
            self.setSingleStep(1)
            self.setVisible(True)

    def updateCurrent(self, current):
        if current >= 0:
            self.setValue(current)

    def triggered(self, action):
        if self.nodeview.viewid == TABLEVIEW_ID:
            f = 1
        else:
            f = self.nodeview.listview.cols
        if action  == QAbstractSlider.SliderSingleStepAdd:
            self.model.seek(self.value() + f)
        elif action == QAbstractSlider.SliderPageStepAdd:
            self.model.seek(self.value() + self.model.visibleRows() - f)
        elif action == QAbstractSlider.SliderSingleStepSub:
            self.model.seek(self.value() - f)
        elif action ==  QAbstractSlider.SliderPageStepSub:
            self.model.seek(self.value() - self.model.visibleRows() - f)
        else:
            return

    def moveTo(self, value):
        self.model.seek(value)
