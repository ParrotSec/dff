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
# Jeremy Mounier <jmo@digital-forensic.org>
# 
from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import QObject, SIGNAL, Qt
from PyQt4.QtGui import QApplication, QCursor

from dff.api.vfs.libvfs import VFS, VLink

class SelectionManager(QObject):
    def __init__(self):
        QObject.__init__(self)
        self.VFS = VFS.Get()
        self._selection = set()

    def add(self, node):
        if node.isDir() or node.hasChildren():
            QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
            self.recurseNodes(node, True)
            QApplication.restoreOverrideCursor()
        else:
            self._selection.add(long(node.this))
        self.emit(SIGNAL("selectionChanged()"))

    def rm(self, node):
        if node.isDir() or node.hasChildren():
            QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
            self.recurseNodes(node, False)
            QApplication.restoreOverrideCursor()
        else:
            try:
                self._selection.remove(long(node.this))
            except KeyError:
                pass
        self.emit(SIGNAL("selectionChanged()"))

    def get(self):
        return self._selection

    def childrenChecked(self, node):
        children = node.children()
        for child in children:
            if not long(child.this) in self._selection:
                return False
        return True

    def isChecked(self, node):
        if long(node.this) in self._selection:
            return True
        return False

    def getNodes(self):
        QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
        nodes = []
        
        for nodeid in self._selection:
            node = self.VFS.getNodeFromPointer(nodeid)
            if isinstance(node, VLink):
                node = node.linkNode()
            nodes.append(node)
        QApplication.restoreOverrideCursor()
        return nodes

    def recurseNodes(self, node, add):
        if add:
            self._selection.add(long(node.this))
        else:
            try:
                self._selection.remove(long(node.this))
            except KeyError:
                pass
        if node.hasChildren():
            childs = node.children()
            for child in childs:
                self.recurseNodes(child, add)

    def clear(self):
        self._selection.clear()
