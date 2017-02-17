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
# 
import os
import sys
from os.path import exists, expanduser, normpath

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import QVariant, SIGNAL, QThread, Qt, QFile, QIODevice, QStringList, QRect, SLOT, QEvent, QString, QSignalMapper, pyqtSignal, pyqtSlot, SLOT
from PyQt4.QtGui import QWidget, QDateTimeEdit, QLineEdit, QHBoxLayout, QLabel, QPushButton, QMessageBox, QListWidget, QTableWidget, QTableWidgetItem, QAbstractItemView, QIcon, QInputDialog, QTableView, QMessageBox, QVBoxLayout, QComboBox, QCheckBox, QHeaderView, QDialog, QTreeWidget, QIntValidator, QDialogButtonBox, QApplication, QCursor, QFileDialog

from dff.api.vfs import vfs
from dff.api.vfs.libvfs import VFS, Node, VLink
from dff.api.types.libtypes import Variant, typeId
from dff.api.filters.libfilters import Filter

from dff.api.gui.model.node_list import NodeListModel
from dff.api.gui.view.node_list import NodeListView
from dff.api.gui.widget.search.thread import SearchThread
from dff.api.gui.widget.search.dico_manager import DicoManager, DicoDialog
from dff.api.gui.widget.search.predefilters import DEFAULT_FILTERS

from dff.ui.gui.widget.SelectMimeTypes import MimeTypesTree
from dff.ui.gui.resources.ui_filter_add import Ui_filterAdd
from dff.ui.gui.resources.ui_filter_mime import Ui_filterMime
from dff.ui.gui.resources.ui_filter_dico import Ui_filterDico
from dff.ui.gui.resources.ui_filter_only import Ui_filterOnly
from dff.ui.gui.resources.ui_search_panel import Ui_searchPanel
from dff.ui.gui.resources.ui_filter_fields import Ui_filterFields
from dff.ui.gui.resources.ui_filter_matchmode import Ui_filterMatchMode
from dff.ui.gui.resources.ui_filter_attributes import Ui_filterAttributes
from dff.ui.gui.resources.ui_filter_mimedialog import Ui_filterMimeDialog
from dff.ui.gui.resources.ui_search_customtable import Ui_searchCustomTable
from dff.ui.gui.resources.ui_filter_conjunction import Ui_filterConjunction


# DEFINES COLUMNS
FIELDS = ["name", "data", "size", "time", "mime", "dico", "deleted","file", "attributes"]
SPECIAL_FIELDSID = range(5, 9)
CONJONCTIONS = ["and", "and not", "or", "or not"]
#ONLY = ["deleted", "file"]
MATCHMODE = ["w(", "re(", "fz(", "f("]
OPERATORS = ["<", "<=", "==", "!=", ">=", ">"]
SIZE_T = [1024, 1024*1024, 1024*1024*1024]
DICO_TYPE = ["name", "data"]
DICO_MATCH = [" any of ", " all of ", " none of "]

DOCUMENT_Q = "\"text\",\"application/pdf\",\"application/vnd.oasis.opendocument.text\",\"application/vnd.oasis.opendocument.graphics\",\"application/vnd.oasis.opendocument.presentation\",\"application/vnd.oasis.opendocument.spreadsheet\",\"application/vnd.oasis.opendocument.chart\",\"application/vnd.oasis.opendocument.formula\",\"application/vnd.oasis.opendocument.database\",\"application/vnd.oasis.opendocument.image\""
IMAGE_Q = "\"image\""
VIDEO_Q = "\"video\""
APPLICATION_Q = "\"application\""
AUDIO_Q = "\"audio\""

class SearchPanel(Ui_searchPanel, QWidget):
  def __init__(self, parent, searchview):
    super(QWidget, self).__init__(parent)
    self.setupUi(self)
    self.filters = CustomFiltersTable(self)
    self.searchFiltersLayout.addWidget(self.filters)
    self.browser = parent
    self.vfs = vfs.vfs()
    self.model = searchview.model
    self.searchview = searchview

    self.matched = 0
    self.searchTH = SearchThread(self)

    self.qmode = {0: "$",
                  1: "/",
                  2: "~",
                  3: "\""}
    self.configure()

  def configure(self):
    # Quick search
    self.connect(self.quickSearch, SIGNAL("clicked(bool)"), self.quickSearchMode)
    # Thread
    self.connect(self.startButton, SIGNAL("clicked(bool)"), self.startSearch)
    self.connect(self.stopButton, SIGNAL("clicked(bool)"), self.searchTH.stopSearch)
    self.connect(self.searchTH, SIGNAL("count"), self.updateProgressbar)
    self.connect(self.searchTH, SIGNAL("match"), self.updateMatchedNodes)
    self.connect(self.searchTH, SIGNAL("finished"), self.searchStoped)
    self.connect(self.searchTH, SIGNAL("started"), self.searchStarted)
    self.connect(self.searchTH, SIGNAL("stoped"), self.searchStoped)
    # Advanced search 
    self.connect(self.advancedSearch, SIGNAL("clicked(bool)"), self.advancedSearchMode)
    # Typebuttons
    self.connect(self.imageType, SIGNAL("clicked()"), self.buttonClicked)
    self.connect(self.videoType, SIGNAL("clicked()"), self.buttonClicked)
    self.connect(self.soundType, SIGNAL("clicked()"), self.buttonClicked)
    self.connect(self.documentType, SIGNAL("clicked()"), self.buttonClicked)
  
  def buttonClicked(self):
    if not self.buttonsChecked():
      self.quickEdit.setEnabled(True)
      self.quickMode.setEnabled(True)
    else:
      self.quickEdit.setEnabled(False)
      self.quickMode.setEnabled(False)
#    self.refreshQueryEdit()
  
  def buttonsChecked(self):
    self.quickEdit.clear()
    if self.imageType.isChecked() or self.videoType.isChecked() or self.soundType.isChecked() or self.documentType.isChecked():
      self.quickEdit.insert(self.generateButtonsClicked())
      return True
    return False

  def generateButtonsClicked(self):
    r = ""
    count = 0
    if self.imageType.isChecked():
      r += DEFAULT_FILTERS["Images"]
      count += 1
    if self.videoType.isChecked():
      if count != 0:
        r += " or "
      r += DEFAULT_FILTERS["Videos"]
      count += 1
    if self.soundType.isChecked():
      if count != 0:
        r += " or "
      r += DEFAULT_FILTERS["Audios"]
      count += 1
    if self.documentType.isChecked():
      if count != 0:
        r += " or "
      r += DEFAULT_FILTERS["Documents"]
      count += 1
    return r

  def startSearch(self):
    query = self.buildQuery()
    if query != None:
      if self.fromRoot.isChecked():
        rootnode = self.vfs.getnode("/")
      else:
        rootnode = self.browser.navigation.currentNode
      if self.browser.filter.isChecked():
        self.browser.viewpan.setCurrentWidget(self.browser.searchview)
      self.model.clearList()
      self.matchedNodeLabel.setText("0")
      self.matched = 0
      r = self.searchTH.setContext(query, rootnode, self.model)
      if r:
        self.searchTH.start()
    else:
      box = QMessageBox(QMessageBox.Critical, self.tr("Error"), self.tr("Please, specify your query"), \
                          QMessageBox.NoButton, self)
      box.exec_()

  def buildQuery(self):
    if self.quickSearch.isChecked():
      query = ""
      if self.quickEdit.text() != "":
        # Check if buttons are checked
        if not self.quickEdit.isEnabled():
          query += str(unicode(self.quickEdit.text()).encode('utf-8'))
        else:
          if self.quickMode.currentIndex() in xrange(0,4):
            pat = self.qmode[self.quickMode.currentIndex()]
            query += "name matches" + pat + str(unicode(self.quickEdit.text()).encode('utf-8')) + pat
          else:
            query += str(unicode(self.quickEdit.text()).encode('utf-8'))
      else:
        return None
      return query
    else:
      return self.filters.buildAllQueries()
      
  def updateProgressbar(self, count):
    self.searchProgress.setValue(count)

  def updateMatchedNodes(self):
    self.matched += 1
    self.matchedNodeLabel.setText(str(self.matched))
    self.searchview.refreshVisible()

  def searchStarted(self):
    QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
    self.searchProgress.setValue(0)
    self.matchedNodeLabel.setText(QString("0"))
    self.startButton.setEnabled(False)
    self.stopButton.setEnabled(True)

  def searchStoped(self):
    self.startButton.setEnabled(True)
    self.stopButton.setEnabled(False)
    if self.browser.filter.isChecked():
      self.browser.viewpan.setCurrentWidget(self.browser.filterview)
      self.browser.filterwidget.resetFilter()
    QApplication.restoreOverrideCursor()

  def quickSearchMode(self, state):
    if state:
      self.advancedSearch.setChecked(False)
    else:
      self.advancedSearch.setChecked(True)

  def advancedSearchMode(self, state):
    if state:
      self.quickSearch.setChecked(False)
    else:
      self.quickSearch.setChecked(True)

# Search filter widget
class CustomFiltersTable(Ui_searchCustomTable, QWidget):
  def __init__(self, parent = None):
    super(QWidget, self).__init__(parent)
    self.setupUi(self)
    self.table.verticalHeader().hide()
    self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
    self.table.setSelectionMode(QAbstractItemView.SingleSelection)
    self.table.setColumnWidth(0, 180)
    self.filters = []
    self.enabled = []

    self.connect(self.newButton, SIGNAL("clicked(bool)"), self.add)
    self.connect(self.deleteButton, SIGNAL("clicked(bool)"), self.remove)
    self.connect(self.editButton, SIGNAL("clicked(bool)"), self.edit)
    self.connect(self.table, SIGNAL("cellClicked(int, int)"), self.cellClick)
    self.connect(self.loadButton, SIGNAL("clicked(bool)"), self.load)
    self.connect(self.saveButton, SIGNAL("clicked(bool)"), self.save)

    self.editButton.setEnabled(False)
    self.deleteButton.setEnabled(False)
    self.saveButton.setEnabled(False)
    
  def buildAllQueries(self):
    query = ""
    enabled = 0
    filters = self.get()
    for count, filt in enumerate(filters):
      if self.filterEnabled(filt):
        if enabled > 0:
          query += " and "
        query += filt.buildRequest()
        enabled += 1
    if query != "":
      return query
    else:
      return None

  def cellClick(self, row, col):
    try:
      filt = self.filters[row]
      self.deleteButton.setEnabled(True)
      if filt.isEditable():
        self.editButton.setEnabled(True)
      else:
        self.editButton.setEnabled(False)
      if self.filterEnabled(filt):
        self.saveButton.setEnabled(True)
      else:
        self.saveButton.setEnabled(False)
      self.refreshQueryEdit()
    except:
      pass

  def addFilter(self, name, query):
    filt = Filter(self, name, query)
    currow = self.table.rowCount()
    self.table.setRowCount(self.table.rowCount() + 1)
    name = QTableWidgetItem(QString(name))
    name.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
    self.table.setItem(currow, 0, name)
    check = QCheckBox()
    check.setChecked(True)
    self.filters.append(filt)
    self.emit(SIGNAL("filterAdded"))
    self.table.horizontalHeader().setResizeMode(1, QHeaderView.ResizeToContents)
    self.refreshQueryEdit()

  def filterState(self, state):
    self.refreshQueryEdit()

  def add(self):
    filt = Filter(self)
    ret = filt.exec_()
    if ret == 1:
      currow = self.table.rowCount()
      self.table.setRowCount(self.table.rowCount() + 1)
      name = QTableWidgetItem(QString(filt.name()))
      name.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
      self.table.setItem(currow, 0, name)
      check = QCheckBox()
      check.setChecked(True)
      self.connect(check, SIGNAL("stateChanged(int)"), self.filterState)
      self.table.setCellWidget(currow, 1, check)
      self.filters.append(filt)
      self.refreshQueryEdit()
      self.emit(SIGNAL("filterAdded"))
      self.table.horizontalHeader().setResizeMode(1, QHeaderView.ResizeToContents)

  def refreshQueryEdit(self):
      self.queryEdit.clear()
      query = self.buildAllQueries()
      if not query: query = ""
      self.queryEdit.insert(query)   

  def remove(self):
    row = self.table.currentRow()
    if row >= 0:
      self.filters.pop(row)
      self.table.removeRow(row)
      self.emit(SIGNAL("filterRemoved"))
      if len(self.filters) == 0:
        self.editButton.setEnabled(False)
      self.refreshQueryEdit()

  def edit(self):
    row = self.table.currentRow()
    filt = self.filters[row]
    ret = filt.exec_()
    if ret == 1:
      cell = self.table.currentItem()
      cell.setText(QString(filt.name()))
    self.refreshQueryEdit()

  def get(self):
    return self.filters

  def closeEvent(self, event):
    pass

  def filterEnabled(self, filt):
    for count, f in enumerate(self.filters):
      if f == filt:
        state = self.table.cellWidget(count, 1).checkState()
        if state == Qt.Unchecked:
          return False
        else:
          return True

  def selectedFilters(self):
    f = []
    for count, filt in enumerate(self.filters):
      state = self.table.cellWidget(count, 1).checkState()
      if state == Qt.Checked:
        f.append(filt)
    return f

  def save(self):
    fdial = QFileDialog()
    sFileName = fdial.getSaveFileName(self, "Save as", os.path.expanduser('~'))
    if sFileName != "":
      sFileName += ".py"
      ufn = str(unicode(sFileName).encode('utf-8'))
      f = open(ufn, "w")
      filts = self.selectedFilters()
      buff = "# -*- coding: utf-8 -*-\n"
      buff += "FILTERS = {\n"
      for filt in filts:
        buff += "\t" + "\"" + filt.name() + "\"" + " : " + "'" + filt.buildRequest() + "'" + ",\n"
      buff += "}\n"
      f.write(buff)
      f.close

  def load(self):
    fdial = QFileDialog()
    sFileName = fdial.getOpenFileName(self, "Save as", os.path.expanduser('~'), "Python (*.py)")
    if sFileName != "":
      try:
        ufn = str(unicode(sFileName).encode('utf-8'))
        location = os.path.dirname(ufn)
        basename = os.path.basename(ufn)
        modname = os.path.splitext(basename)
        sys.path.append(location)
        f = __import__(modname[0])
        for name, query in f.FILTERS.iteritems():
          self.addFilter(name, query)
      except:
        pass

class Filter(Ui_filterAdd, QDialog):
  def __init__(self, filtertable, fname=None, query=None):
    super(QDialog, self).__init__(filtertable)
    self.filtertable = filtertable
    self.setupUi(self)
    self.editable = False
    self.defaultquery = None
    self.fname = None
    if (fname == None) and (query == None):
      self.editable = True
      self.filterRequest = FilterRequests(self)
      self.requestLayout.addWidget(self.filterRequest)
    else:
      self.defaultquery = query
      self.fname = fname

  def reject(self):
    QDialog.reject(self)

  def accept(self):
    if not self.name().isEmpty():
      QDialog.accept(self)
    else:
      box = QMessageBox(QMessageBox.Critical, self.tr("Error"), self.tr("Please, specify a query name"), \
                          QMessageBox.NoButton, self)
      box.exec_()
    
  def isEditable(self):
    return self.editable

  def name(self):
    if self.editable:
      return self.filterName.text()
    else:
      return self.fname

  def buildRequest(self):
    if self.editable:
      row = 0
      res = "("
      while row < self.filterRequest.rowCount():
        if row > 0:
          conj = self.filterRequest.cellWidget(row, 0)
          res += " " + CONJONCTIONS[conj.conjunctionCombo.currentIndex()] + " "
        widget = self.filterRequest.cellWidget(row, 2)
        res +=  widget.request()
        row += 1
      res += ")"
      return res
    else:
      return self.defaultquery

class FilterRequests(QTableWidget):
  def __init__(self, parent = None):
    super(QTableWidget, self).__init__(parent)
    self.parent = parent
    self.configure()
    # Keep a list of FieldCombo object
    self.fieldMapper = []
    self.removeMapper = []
    self.addRequest()

  def configure(self):
    self.setColumnCount(5)
    self.setRowCount(0)
    self.verticalHeader().setDefaultSectionSize(30)
    self.horizontalHeader().setDefaultSectionSize(30)
    self.horizontalHeader().setResizeMode(1, QHeaderView.ResizeToContents)
    self.horizontalHeader().setResizeMode(2, QHeaderView.Stretch)
    self.horizontalHeader().setResizeMode(3, QHeaderView.ResizeToContents)
    self.horizontalHeader().setResizeMode(4, QHeaderView.ResizeToContents)
    self.setSelectionMode(QAbstractItemView.NoSelection)
    self.horizontalHeader().setStretchLastSection(False)
    self.setShowGrid(False)
    self.horizontalHeader().hide()
    self.verticalHeader().hide()

  def addRequest(self, widget=None):
    currow = self.rowCount()
    self.setRowCount(self.rowCount() + 1)
    # Add conjonctions if not First widget
    if len(self.fieldMapper) != 0:
      conjonction = ConjonctionCombo(self)
      self.setCellWidget(currow, 0, conjonction)
      self.horizontalHeader().setResizeMode(0, QHeaderView.ResizeToContents)
    else:
      empty = QTableWidgetItem(QString(""))
      empty.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
      self.setItem(currow, 0, empty)
    # Add Field choice
    fields = FieldCombo(self)
    self.connect(fields, SIGNAL("fieldChanged"), self.changeFilterType)
    self.setCellWidget(currow, 1,  fields)
    self.fieldMapper.append(fields.fieldCombo)
    # Add Widget
    if widget == None:
      widget = NameRequest(self)
    self.setCellWidget(currow, 2, widget)
    # Add request button
    add = self.createAddRequestButton()
    self.setCellWidget(currow, 3, add)
    # Remove request button
    rm = removeRequestButton()
    self.removeMapper.append(rm)
    self.connect(rm, SIGNAL("removeRequest"), self.removeRequest)
    self.setCellWidget(currow, 4, rm)

  def changeFilterType(self, fieldwidget, index):
    # ["name", "data", "size", "time", "mime", "file", "deleted", "attributes"]
    if fieldwidget in self.fieldMapper:
      row = self.fieldMapper.index(fieldwidget)
      ftype = fieldwidget.currentIndex()
      if ftype == FIELDS.index("name"):
        widget = NameRequest(self)
      elif ftype == FIELDS.index("data"):
        widget = NameRequest(self, data=True)
      elif ftype == FIELDS.index("size"):
        widget = SizeRequest(self)
      elif ftype == FIELDS.index("time"):
        widget = DateRequest(self)
      elif ftype == FIELDS.index("mime"):
        widget = MimeRequest(self)
      elif ftype == FIELDS.index("dico"):
        widget = DicoRequest(self)
      elif ftype == FIELDS.index("deleted"):
        widget = OnlyRequest(self, field="deleted")
      elif ftype == FIELDS.index("file"):
        widget = OnlyRequest(self, field="file")
      elif ftype == FIELDS.index("attributes"):
        widget = AttributeRequest(self)
      else:
        return
      self.setCellWidget(row, 2, widget)

  def removeRequest(self, rmbutton):
    if (rmbutton in self.removeMapper):
      if self.removeMapper.index(rmbutton) > 0:
        row = self.removeMapper.index(rmbutton)
        self.removeRow(row)
        self.fieldMapper.pop(row)
        self.removeMapper.pop(row)

  def createAddRequestButton(self):
    addRequestButton = QPushButton()
    addRequestButton.setIcon(QIcon(":add.png"))
    self.connect(addRequestButton, SIGNAL("clicked()"), self.addRequest)
    return addRequestButton

class removeRequestButton(QPushButton):
  def __init__(self):
    QPushButton.__init__(self)
    self.setIcon(QIcon(":remove.png"))
    self.connect(self, SIGNAL("clicked(bool)"), self.removeMapper)

  def removeMapper(self):
    self.emit(SIGNAL("removeRequest"), self)

class Request(QWidget):
  def __init__(self, parent):
    QWidget.__init__(self, parent)
    self.hlayout = QHBoxLayout(self)
    self.hlayout.setMargin(2)
    self.setLayout(self.hlayout)

class ConjonctionCombo(Ui_filterConjunction, Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.setupUi(self)
    self.hlayout.addWidget(self.conjunctionCombo)

class NameRequest(Ui_filterMatchMode, Request):
  def __init__(self, parent, data=False):
    Request.__init__(self, parent)
    self.data = data
    self.setupUi(self)
    self.setContent()
    self.setMatchMode()
    self.setCase()

  def setContent(self):
    self.content = QLineEdit(self)
    self.hlayout.addWidget(self.content)

  def setMatchMode(self):
    self.hlayout.addWidget(self.matchModeCombo)

  def setCase(self):
    self.casse.setChecked(True)
    self.hlayout.addWidget(self.casse)

  def request(self):
    result = "("
    if not self.data:
      result += "name matches "
    else:
      result += "data matches "
    result += MATCHMODE[self.matchModeCombo.currentIndex()]
    result += "\"" + str(unicode(self.content.text()).encode('utf-8')) + self.case() + ")"
    return result

  def case(self):
    if not self.casse.isChecked():
      return  "\",i)"
    else:
      return "\")"

class SizeRequest(Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.setOperators()
    self.setContent()
    self.setSizeType()

  def setOperators(self):
    self.operatorCombo = OperatorCombo(self)
    self.hlayout.addWidget(self.operatorCombo)

  def setContent(self):
    self.content = QLineEdit(self)
    self.validator = QIntValidator(0,2147483647, self)
    self.content.setValidator(self.validator)
    self.hlayout.addWidget(self.content)

  def setSizeType(self):
    self.stype = QComboBox(self)
    self.stype.addItem(QString("KB"))
    self.stype.addItem(QString("MB"))
    self.stype.addItem(QString("GB"))
    self.hlayout.addWidget(self.stype)

  def request(self):
    operator = str(self.operatorCombo.currentText())
    factor = SIZE_T[self.stype.currentIndex()]
    size = self.content.text().toULongLong()[0]
    size = size * factor
    res = "(size " + operator + " " + str(size) + ")"
    return res

class DateRequest(Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.setOperators()
    self.setDateTime()

  def setOperators(self):
    self.operatorCombo = OperatorCombo(self)
    self.hlayout.addWidget(self.operatorCombo)

  def setDateTime(self):
    self.datetime = QDateTimeEdit(self)
    self.datetime.setCalendarPopup(True)
    self.hlayout.addWidget(self.datetime, 50)

  def request(self):
    res = "(time " +  str(self.operatorCombo.currentText())
    date_time = self.datetime.dateTime()
    res += str(date_time.toString("yyyy-MM-ddThh:mm:ss")) + ")"
    return res

class MimeRequest(Ui_filterMime, Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.setupUi(self)
    self.setContent()
    self.setSelectButton()

  def setContent(self):
    self.content.setReadOnly(True)
    self.hlayout.addWidget(self.content, 50)

  def setSelectButton(self):
    self.hlayout.addWidget(self.selectButton)
    self.connect(self.selectButton, SIGNAL("clicked()"), self.selectMimeDialog)

  def selectMimeDialog(self):
    dialog = MimeDialog(self)
    ret = dialog.exec_()
    if ret == 1:
      result = dialog.selectedTypes()
      self.content.clear()
      self.content.setText(result)

  def request(self):
    res = "(mime in[" + str(unicode(self.content.text()).encode('utf-8')) + "])"
    return res

class MimeDialog(Ui_filterMimeDialog, QDialog):
  def __init__(self, parent):
    QDialog.__init__(self, parent)
    self.setupUi(self)
    self.mime = MimeTypesTree(self.treeWidget)

  def selectedTypes(self):
    mimes = self.mime.selectedItems()
    result = ""
    for count, mime in enumerate(mimes):
      result += "\"" + mime + "\""
      if count < len(mimes) - 1:
        result += ","
    return result

class DicoRequest(Ui_filterDico, Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.setupUi(self)
    self.setContent()
    self.dicos = []

  def setContent(self):
    self.hlayout.addWidget(self.dicoPath, 50)
    self.hlayout.addWidget(self.dicoManager, 5)
    self.hlayout.addWidget(self.dicoType, 10)
    self.hlayout.addWidget(self.dicoMatch, 10)
    self.connect(self.dicoManager, SIGNAL("clicked()"), self.selectDico)

  def selectDico(self):
    dialog = DicoDialog(self)
    r = dialog.exec_()
    if r > 0:
      self.dicos = dialog.manager.selectedDicoNames()
      if self.dicos != None:
        label = str()
        for dico in self.dicos:
          label += dico
        self.dicoPath.clear()
        self.dicoPath.insert(QString.fromUtf8(label))

  def request(self):
    res = str("(")
    if len(self.dicos) > 0:
      res += DICO_TYPE[self.dicoType.currentIndex()] + " matches"
      res += DICO_MATCH[self.dicoMatch.currentIndex()] + "["
      for count, dico in enumerate(self.dicos):
        res += dico + ":"
        if count < len(self.dicos) - 1:
          res += ","
      res += "])"
    return res
      
class OnlyRequest(Ui_filterOnly, Request):
  def __init__(self, parent, field):
    Request.__init__(self, parent)
    self.setupUi(self)
    self.field = field
    self.setOnly()

  def setOnly(self):
    self.hlayout.addWidget(self.onlyCombo)

  def request(self):
    index = self.onlyCombo.currentIndex()
    # Deleted
    if self.field == "deleted":
      res = "(deleted == "
    elif self.field == "file":
      res = "(file == "
    # Files
    if index == 0:
      res += "true)"
    else:
      res += "false)"
    return res

class AttributeRequest(Ui_filterAttributes, Request):
  def __init__(self, parent, iss=True):
    Request.__init__(self, parent)
    self.setupUi(self)
    self.setOperators()
    self.setShape()

  def setOperators(self):
    self.operatorCombo = OperatorCombo(self, attrmode=True)
    self.hlayout.addWidget(self.operatorCombo)

  def setShape(self):
    self.hlayout.addWidget(self.key)
    self.hlayout.addWidget(self.operatorCombo)
    self.hlayout.addWidget(self.value)

  def request(self):
    res = "(@" + str(unicode(self.key.text()).encode('utf-8')) + "@ "
    res += str(self.operatorCombo.currentText()) + " \""
    res += str(unicode(self.value.text()).encode('utf-8')) + "\")"
    return res

class FieldCombo(Ui_filterFields, Request):
  def __init__(self, parent):
    Request.__init__(self, parent)
    self.setupUi(self)
    self.hlayout.addWidget(self.fieldCombo)

    self.connect(self.fieldCombo, SIGNAL("currentIndexChanged(int)"), self.indexChangedMapper)

  def indexChangedMapper(self, index):
    self.emit(SIGNAL("fieldChanged"), self.fieldCombo, index)

class OperatorCombo(QComboBox):
  def __init__(self, parent, attrmode=False):
    QComboBox.__init__(self, parent)
    if attrmode:
      self.addItem(QString("matches"))
    for op in OPERATORS:
      self.addItem(QString(op))

