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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 

import os, types

from PyQt4.QtGui import QWidget, QMenu, QDialog, QLabel, QVBoxLayout, QSplitter, QDialogButtonBox, QFormLayout, QCheckBox, QComboBox, QLineEdit, QTextEdit, QListWidget, QHBoxLayout, QPushButton, QIcon, QFileDialog, QAbstractItemView, QRegExpValidator, QListWidgetItem, QApplication
from PyQt4.QtCore import Qt, QEvent, SIGNAL, QRegExp, QSize, QString

from dff.api.vfs import vfs 
from dff.api.vfs.libvfs import VFS, Node
from dff.api.types.libtypes import typeId

class DialogNodeBrowser(QDialog):
    def __init__(self, parent=None):
        QDialog.__init__(self, parent)
        self.title = QLabel("Select a node in the Virtual File System :")
        self.createLayout()
        self.createButtons()

    def createLayout(self):
        self.baseLayout = QVBoxLayout(self)
        mw = QApplication.instance().mainWindow
        self.browser = mw.getNodeBrowser()
        self.baseLayout.addWidget(self.browser)
        self.setLayout(self.baseLayout)

    def createButtons(self):
        self.buttonBox = QDialogButtonBox()
        self.buttonBox.setStandardButtons(QDialogButtonBox.Cancel|QDialogButtonBox.Ok)
        self.connect(self.buttonBox, SIGNAL("accepted()"),self.accept)
        self.connect(self.buttonBox, SIGNAL("rejected()"),self.reject)
        self.baseLayout.addWidget(self.buttonBox)
        
    def getSelectedNodes(self):
        if len(self.browser.selection.get()) == 0:
            nodes = [self.browser.browserview.model.currentNode()]
        else:
            nodes = self.browser.selection.getNodes()
        return nodes

    def getSelectedNode(self):
        try:
            n = self.getSelectedNodes()[0]
            return n
        except:
            return None

    def changeEvent(self, event):
        """ Search for a language change event
        
        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.model.translation()
        else:
            QWidget.changeEvent(self, event)


class layoutManager(QWidget):
    '''Create a layout manager which will help widget creation and data managment
    The system work with a key / value system and return python type data (ex: str, int, long, list, tupple, etc..)
    '''
    def __init__(self, displaykey=False):
        QWidget.__init__(self)
        self.layout = QFormLayout()
        self.layout.setMargin(0)
        self.widgets = {}
        self.displaykey = displaykey
        self.setLayout(self.layout)
        self.translation()


    def overwriteKeys(self, key):
        '''
        Check if inserted key already exists in the layout system
        '''
        for k, v in self.widgets.iteritems():
            if k == key:
                return True
        return False

    def addBool(self, key, state = False):
        '''
        Create a non-exclusive checkbox widget and add it into the layout. It permit you to create Bool data representations
        '''
        if not self.overwriteKeys(key):
            if type(key).__name__=='str':
                w = QCheckBox(key)
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
            else:
                return -1
        else:
            return -1
        return 1

    def addList(self, key, predefs, editable=False):
        if len(predefs) > 0 and not self.overwriteKeys(key):
            # Check if value list has the same type
            if type(key) == types.StringType:
                w = QComboBox()
		self.connect(w, SIGNAL("currentIndexChanged(QString)"), self.argumentChanged)
                w.setEditable(editable)
                w.setValidator(QIntValidator())
                for value in predefs:
                    if type(value).__name__=='str':
                        if w.findText(value) == -1:
                            w.addItem(value)
                    elif type(value).__name__=='int':
                        if w.findText(str(value)) == -1:
                            w.addItem(str(value))
                    else:
                        return -1
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else: 
                return -1
        else:
            return -1

    def addSingleArgument(self, key, predefs, typeid, editable=False):
        if not self.overwriteKeys(key):
            if type(key) == types.StringType:
                if len(predefs) > 0:
                    w = QComboBox()
		    self.connect(w, SIGNAL("editTextChanged(QString)"), self.argumentChanged)
		    self.connect(w, SIGNAL("currentIndexChanged(QString)"), self.argumentChanged)
                    w.setEditable(editable)
                    for value in predefs:
                        w.addItem(value.toString())
                else:
                    w = QLineEdit()
		    self.connect(w, SIGNAL("editingFinished()"), self.argumentChanged)
                    if typeid not in (typeId.String, typeId.Char, typeId.Node, typeId.Path):
                        w.insert("0")
                    w.setReadOnly(not editable)
                w.setValidator(fieldValidator(self, typeid))
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else: 
                return -1
        else:
            return -1

    def addString(self, key, value=""):
        if not self.overwriteKeys(key):
            if type(key).__name__=='str':
                w = QLineEdit()
		self.connect(w, SIGNAL("editingFinished()"), self.argumentChanged)
                w.insert(value)
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else:
                return -1
        else:
            return -1
    
    def addText(self, key,  value=""):
        if not self.overwriteKeys(key):
            if type(key).__name__=='str':
                w = QTextEdit()
		self.connect(w, SIGNAL("textChanged()"), self.argumentChanged)
                w.setPlainText(value)
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else:
                return -1
        else:
            return -1

    def addListArgument(self, key, typeid, predefs, editable=False, config=None):
        if not self.overwriteKeys(key) and type(key) == types.StringType:
            w = multipleListWidget(self, typeid, predefs, editable)
            if not self.displaykey:
                self.layout.addRow(w)
            else:
                self.layout.addRow(key, w)
            self.widgets[key] = w.valuelist
	    if config:
	      w.addParameterConfig(config)
            return 1
        else:
            return -1

    def addPathList(self, key, typeid, predefs, selectednodes):
        if not self.overwriteKeys(key) and type(key).__name__=='str':
            layout = QVBoxLayout()
            listpathcontainer = QListWidget() ##XXX
            listpathcontainer.setDragDropMode(QAbstractItemView.InternalMove)
            if len(predefs) > 0:
                if not self.checkUnifiedTypes(predefs):
                    return -1
                for predef in predefs:
                    listpathcontainer.insertItem(listpathcontainer.count() + 1, str(predef))
            if selectednodes and len(selectednodes) > 0:
                for node in selectednodes:
		   if type(node) == Node and typeid == typeId.Node:
                        listpathcontainer.insertItem(listpathcontainer.count() + 1, QString.fromUtf8(node.absolute())) 
		   elif type(node) != Node:
			listpathcontainer.insertItem(listpathcontainer.count() + 1, node)
            hbox = QHBoxLayout()
            buttonbox = QDialogButtonBox()
            if typeid == typeId.Path:
                combo = QComboBox()
	        self.connect(combo, SIGNAL("editTextChanged(QString)"), self.argumentChanged)
		self.connect(combo, SIGNAL("currentIndexChanged(QString)"), self.argumentChanged)
                combo.addItem(self.inputFile)
                combo.addItem(self.inputDirectory)
                add = addLocalPathButton(self, key, listpathcontainer, combo)
            else:
                add = addLocalPathButton(self, key, listpathcontainer, nodetype=True)
            buttonbox.addButton(add, QDialogButtonBox.ActionRole)
            rm = rmLocalPathButton(self, listpathcontainer)
            buttonbox.addButton(rm, QDialogButtonBox.ActionRole)

            self.connect(add, SIGNAL("clicked()"), self.argumentChanged)
            self.connect(rm, SIGNAL("clicked()"), self.argumentChanged)

            hbox.addWidget(buttonbox, 3, Qt.AlignLeft)
            if typeid == typeId.Path:
                hbox.addWidget(combo, 1, Qt.AlignRight)
            layout.addLayout(hbox, 0)
            layout.addWidget(listpathcontainer, 2)

            if not self.displaykey:
                self.layout.addRow(layout)
            else:
                self.layout.addRow(key, layout)
            self.widgets[key] = listpathcontainer
            return 1
        else:
            return -1

    def addPath(self, key, typeid, predefs, selectednodes, editable=False, config=None):
        if config:
	  predefs.push_front(config[0]) 
        if not self.overwriteKeys(key) and type(key).__name__=='str':
            vbox = QVBoxLayout()
            if typeid == typeId.Path:
                combo = QComboBox()
	        self.connect(combo, SIGNAL("editTextChanged(QString)"), self.argumentChanged)
		self.connect(combo, SIGNAL("currentIndexChanged(QString)"), self.argumentChanged)
                combo.addItem(self.inputFile)
                combo.addItem(self.inputDirectory)
                vbox.addWidget(combo)
            layout = QHBoxLayout()
            if len(predefs) > 0 or len(selectednodes) > 0:
                pathcontainer = QComboBox()
	        self.connect(pathcontainer, SIGNAL("editTextChanged(QString)"), self.argumentChanged)
		self.connect(pathcontainer, SIGNAL("currentIndexChanged(QString)"), self.argumentChanged)
                pathcontainer.setEditable(editable)
                for value in predefs:
                    if typeid == typeId.Node:
                        pathcontainer.addItem(value.value().name())
                    else:
                        pathcontainer.addItem(value.toString())
                if typeid == typeId.Node:
                    for node in selectednodes:
                        pathcontainer.addItem(QString.fromUtf8(node.absolute()))
            else:
                pathcontainer = QLineEdit()
                pathcontainer.setReadOnly(not editable)
		self.connect(pathcontainer, SIGNAL("editingFinished()"), self.argumentChanged)
            if typeid == typeId.Path:
                browse = addLocalPathButton(self, key, pathcontainer, inputchoice=combo)
            else:
                browse = addLocalPathButton(self, key, pathcontainer, nodetype=True)
            layout.addWidget(pathcontainer, 2)
            layout.addWidget(browse, 0)
            vbox.addLayout(layout)
            if not self.displaykey:
                self.layout.addRow(vbox)
            else:
                self.layout.addRow(key, vbox)
            self.widgets[key] = pathcontainer
            return 1
        else:
            return -1


    def checkUnifiedTypes(self, values):
        if len(values) == 0:
            return
        vtype = type(values[0]).__name__
        for v in values:
            if type(v).__name__!=vtype:
                return False
        return True

    def get(self, key):
        for k, v in self.widgets.iteritems():
            if k == key:
                if isinstance(self.widgets[k], QLineEdit):
                    return str(v.text().toUtf8())
                elif isinstance(self.widgets[k], QListWidget):
                    items = []
                    for index in xrange(self.widgets[k].count()): 
                        items.append(str(self.widgets[k].item(index).text().toUtf8())) 
                    return items
                elif isinstance(self.widgets[k], QCheckBox):
                    state = self.widgets[k].checkState()
                    if state == Qt.Unchecked:
                        return False
                    else:
                        return True
                elif isinstance(self.widgets[k], QTextEdit):
                    return str(self.widgets[k].toPlainText().toUtf8())
                elif isinstance(self.widgets[k], QComboBox):
                    return str(self.widgets[k].currentText().toUtf8())
                else:
                    return -1

    def argumentChanged(self, event = None):
	self.emit(SIGNAL("argumentChanged()"))

    def translation(self):
        self.inputFile = self.tr("File")
        self.inputDirectory = self.tr("Directory")


    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
            self.translation()
        else:
            QWidget.changeEvent(self, event)


class fieldValidator(QRegExpValidator):
    def __init__(self, parent, typeid):
        QRegExpValidator.__init__(self, parent)
        self.typeid = typeid
        self.init()

    def init(self):
        if self.typeid in (typeId.Int16, typeId.Int32, typeId.Int64):
            exp = "^(\+|-)?\d+$"
        elif self.typeid in (typeId.UInt16, typeId.UInt32, typeId.UInt64):
            exp = "^\d+$"
        else:
            exp = "^.+$"
        regexp = QRegExp(exp)
        regexp.setCaseSensitivity(Qt.CaseInsensitive)
        self.setRegExp(regexp)


class multipleListWidget(QWidget):
    def __init__(self, parent, typeid, predefs, editable):
        QWidget.__init__(self)
        self.parent = parent
        self.typeid = typeid
        self.editable = editable
        self.predefs = predefs
        self.init()

    def init(self):
        self.vbox = QVBoxLayout()
        self.vbox.setSpacing(5)
        self.vbox.setMargin(0)
        self.createHeader()
        self.valuelist = QListWidget()
        self.vbox.addWidget(self.valuelist)
        self.setLayout(self.vbox)

    def createHeader(self):
        self.whead = QWidget()
        self.headerlayout = QHBoxLayout()
        self.headerlayout.setSpacing(0)
        self.headerlayout.setMargin(0)
        if self.typeid in (typeId.Node, typeId.Path) and self.editable:
            self.addPath()
        else:
            self.addSingleArgument()

        self.addButton = QPushButton(QIcon(":add.png"), "")
        self.rmButton = QPushButton(QIcon(":del_dump.png"), "")
        self.addButton.setIconSize(QSize(16, 16))
        self.rmButton.setIconSize(QSize(16, 16))

        self.connect(self.addButton, SIGNAL("clicked()"), self.addParameter)
        self.connect(self.rmButton, SIGNAL("clicked()"), self.rmParameter)
        self.connect(self.addButton, SIGNAL("clicked()"), self.parent.argumentChanged)
        self.connect(self.rmButton, SIGNAL("clicked()"), self.parent.argumentChanged)

        self.headerlayout.addWidget(self.addButton, 0)
        self.headerlayout.addWidget(self.rmButton, 0)
        self.whead.setLayout(self.headerlayout)
        self.vbox.addWidget(self.whead)

    def addParameterConfig(self, config):
       try : 
        if len(config) :
          for item in config:  
            self.valuelist.insertItem(self.valuelist.count() + 1, item)
       except TypeError:
	 self.valuelist.insertItem(self.valuelist.count() + 1, config)

    def addParameter(self):
        if isinstance(self.container, QComboBox):
            item = self.container.currentText()
        else:
            item = self.container.text()
        if len(self.valuelist.findItems(item, Qt.MatchExactly)) == 0:
            self.valuelist.insertItem(self.valuelist.count() + 1, item) 

    def rmParameter(self):
        selected = self.valuelist.selectedItems()
        for item in selected:
            row = self.valuelist.row(item)
            self.valuelist.takeItem(row)        

    def addSingleArgument(self):
        if len(self.predefs) > 0:
            self.container = QComboBox()
            for value in self.predefs:
                if self.typeid == typeId.Node:
                    self.container.addItem(value.value().name())
                else:
                    self.container.addItem(value.toString())
                self.container.setEditable(self.editable)
        else:
            self.container = QLineEdit()
            self.container.setReadOnly(self.editable)
        self.headerlayout.addWidget(self.container, 2)

    def addPath(self):
        if len(self.predefs) > 0:
            self.container = QComboBox()
            self.container.setReadOnly(False)
            for value in self.predefs:
                self.container.addItem(value.toString())
        else:
            self.container = QLineEdit()
            self.container.setReadOnly(False)
            if self.typeid == typeId.Path:
                browse = addLocalPathButton(self, key, self.container, isdir=False)
            else:
                browse = addLocalPathButton(self, key, self.container, isdir=False, nodetype=True)
        self.headerlayout.addWidget(self.container, 2)
        self.headerlayout.addWidget(browse, 0)

    def addPredefValue(self):
        selected = self.predefs.selectedItems()
        for item in selected:
            self.valuelist.insertItem(self.valuelist.count() + 1, item.text())

class addLocalPathButton(QPushButton):
    lastPath = os.path.expanduser('~') 
    def __init__(self, parent, key, container, inputchoice=None, nodetype=False):
        if isinstance(container, QListWidget):
            QPushButton.__init__(self, QIcon(":add.png"), "")
        else:
            QPushButton.__init__(self, QIcon(":folder.png"), "...")
        self.setIconSize(QSize(16, 16))
        self.manager = parent
        self.inputcombo = inputchoice
        self.ckey = key
        self.container = container
        self.parent = container
        self.nodetype = nodetype
        self.connect(self, SIGNAL("clicked()"), self.browse)
       
    def setLastPath(self, path):
       path = str(path.toUtf8())
       if path.rfind('/') != -1:
	  addLocalPathButton.lastPath = path[:path.rfind('/') + 1]
       elif path.rfind('\\') != -1:
	  addLocalPathButton.lastPath = path[:path.rfind('\\') + 1]

    def browse(self):
        title = "Load " + str(self.ckey)
        if not self.nodetype:
            if self.inputcombo and self.inputcombo.currentIndex() == 0:
                if isinstance(self.container, QListWidget):
                    sFileName = QFileDialog.getOpenFileNames(self.parent, title, addLocalPathButton.lastPath)
		    if len(sFileName) > 0:
 		      self.setLastPath(sFileName[0])
                    for name in sFileName:
                        item = QListWidgetItem(name, self.container)
                elif isinstance(self.container, QLineEdit):
                    sFileName = QFileDialog.getOpenFileName(self.parent, title, addLocalPathButton.lastPath)
		    self.setLastPath(sFileName)
                    self.container.clear()
                    self.container.insert(sFileName)
		elif isinstance(self.container, QComboBox):
                    sFileName = QFileDialog.getOpenFileName(self.parent, title, addLocalPathButton.lastPath)
		    self.setLastPath(sFileName)
		    self.container.insertItem(0, sFileName)
		    self.container.setCurrentIndex(0) 
                else:
                    return -1
            else:
                sFileName = QFileDialog.getExistingDirectory(self.parent, title, addLocalPathButton.lastPath, QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks)
		self.setLastPath(sFileName) 
                if isinstance(self.container, QListWidget):
                    if sFileName:
                        item = QListWidgetItem(sFileName, self.container)
                elif isinstance(self.container, QComboBox):
                    self.container.insertItem(0, sFileName)
		    self.container.setCurrentIndex(0)
	        else:
                    self.container.insert(sFileName)
            self.manager.emit(SIGNAL("managerChanged"))
        else:
            BrowseVFSDialog = DialogNodeBrowser(self)
            if isinstance(self.container, QListWidget) or isinstance(self.container, QComboBox):
                iReturn = BrowseVFSDialog.exec_()
                if iReturn :
                    nodes = BrowseVFSDialog.getSelectedNodes()
                    index = 0
                    if len(nodes):
                        for node in nodes:
                            self.container.insertItem(index, QString.fromUtf8(node.absolute()))
                            index += 1
                        if isinstance(self.container, QListWidget):
                            self.container.setCurrentItem(self.container.item(0))
                        else:
                            self.container.setCurrentIndex(0)
            else:
                iReturn = BrowseVFSDialog.exec_()
                if iReturn :
                    node = BrowseVFSDialog.getSelectedNode()
                    print node
                    if node:
                        self.container.clear()
                        self.container.insert(QString.fromUtf8(node.absolute()))
            BrowseVFSDialog.browser.__del__()


class rmLocalPathButton(QPushButton):
    def __init__(self, parent, container):
        QPushButton.__init__(self, QIcon(":del_dump.png"),"")
        self.setIconSize(QSize(16, 16))
        self.container = container
        self.manager = parent
        self.connect(self, SIGNAL("clicked()"), self.rm)

    def rm(self):
        selected = self.container.selectedItems()
        for item in selected:
            row = self.container.row(item)
            self.container.takeItem(row)
        self.manager.emit(SIGNAL("managerChanged"))

