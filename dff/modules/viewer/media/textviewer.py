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
#  Jeremy MOUNIER <jmo@digital-forensic.org>

__dff_module_cat_version__ = "1.0.0"

from PyQt4.QtCore import Qt, QString, SIGNAL, QTextCodec
from PyQt4.QtGui import QWidget, QTextCursor, QTextEdit, QTextOption, QScrollBar, QAbstractSlider, QHBoxLayout, QListWidget, QVBoxLayout, QSplitter, QSizePolicy

from dff.api.vfs import vfs 
from dff.api.types.libtypes import Argument, typeId
from dff.api.module.module import Module 
from dff.api.module.script import Script

class TextEdit(QTextEdit):
  def __init__(self, cat):
    QTextEdit.__init__(self)
    self.cat = cat
    self.scroll = self.cat.scroll
    self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    self.setReadOnly(1)

    self.setWordWrapMode(QTextOption.NoWrap)

  def wheelEvent(self, event):
    v = self.scroll.value()
    if event.delta() > 0:
      trig = v - 5
      if trig >= self.scroll.min:
        self.cat.read(trig)
        self.scroll.setValue(trig)
    else:
      trig = v + 5
      if trig < self.scroll.max:
        self.cat.read(trig)
        self.scroll.setValue(trig)


class Scroll(QScrollBar):
    def __init__(self, parent):
      QScrollBar.__init__(self, parent)
      self.cat = parent
      self.init()
      self.initCallBacks()
      self.setValues()

    def init(self):
      self.min = 0
      self.single = 1
      self.page = 32
      self.max = self.cat.lines - 1

    def initCallBacks(self):
      self.connect(self, SIGNAL("sliderMoved(int)"), self.moved) 
      self.connect(self, SIGNAL("actionTriggered(int)"), self.triggered) 

    def setValues(self):
      self.setMinimum(self.min)
      self.setMaximum(self.max)
      self.setSingleStep(self.single)
      self.setPageStep(self.page)
      self.setRange(self.min, self.max)

    def triggered(self, action):
      if action == QAbstractSlider.SliderSingleStepAdd:
        trig = self.value() + 1
        if trig <= self.max:
          self.cat.read(trig)
      elif action == QAbstractSlider.SliderSingleStepSub:
        trig = self.value() - 1
        if trig >= self.min:
          self.cat.read(trig)
      elif action == QAbstractSlider.SliderPageStepSub:
        trig = self.value() - 5
        if trig >= self.min:
          self.cat.read(trig)
      elif action == QAbstractSlider.SliderPageStepAdd:
        trig = self.value() + 5
        if trig <= self.max:
          self.cat.read(trig)

    def moved(self, value):
      if value == self.max:
        value -= 5
      self.cat.read(value)


class CAT(QSplitter, Script):
  def __init__(self):
    Script.__init__(self, "cat")
    self.vfs = vfs.vfs()
    self.type = "cat"
    self.icon = None
    self.currentCodec = "UTF-8"
 
  def start(self, args):
    self.args = args
    try:
      self.node = args["file"].value()
    except:
      pass

  def g_display(self):
    QSplitter.__init__(self)
    self.offsets = self.linecount()
    self.initShape()

    self.read(0)

  def initShape(self):
    self.hbox = QHBoxLayout()
    self.hbox.setContentsMargins(0, 0, 0, 0)

    self.listWidget = QListWidget()
    self.listWidget.setSortingEnabled(True)
    for codec in QTextCodec.availableCodecs():
	 self.listWidget.addItem(str(codec))
    item = self.listWidget.findItems('UTF-8', Qt.MatchExactly)[0]
    self.listWidget.setCurrentItem(item)
    self.listWidget.scrollToItem(item)

    textAreaWidget = QWidget()
    self.hbox.addWidget(self.listWidget) 
    self.connect(self.listWidget, SIGNAL("itemSelectionChanged()"), self.codecChanged)

    self.scroll = Scroll(self)
    self.text = TextEdit(self)

    self.hbox.addWidget(self.text)
    self.hbox.addWidget(self.scroll)

    textAreaWidget.setLayout(self.hbox)

    self.addWidget(self.listWidget)
    self.addWidget(textAreaWidget) 
    self.setStretchFactor(0, 0)  
    self.setStretchFactor(1, 1)  
 
  def codecChanged(self):
     self.currentCodec = self.listWidget.selectedItems()[0].text()
     self.read(self.scroll.value())

  def read(self, line):
    self.vfile = self.node.open()
    padd = 0
    if line > padd:
      padd = 1
    self.vfile.seek(self.offsets[line]+padd)
    self.text.clear()
    codec = QTextCodec.codecForName(self.currentCodec)
    decoder = codec.makeDecoder()
    self.text.textCursor().insertText(decoder.toUnicode(self.vfile.read(1024*10)))
    self.text.moveCursor(QTextCursor.Start)
    self.vfile.close()

  def linecount(self):
    offsets = [0]
    self.vfile = self.node.open()
    offsets.extend(self.vfile.indexes('\n'))
    self.vfile.close()
    self.lines = len(offsets)
    return offsets

  def updateWidget(self):
	pass

  def c_display(self):
    file = self.node.open()
    fsize = self.node.size()
    size = 0
    self.buff = ""
    while size < fsize:
      try:
       tmp = file.read(4096)
      except vfsError, e:
        print self.buff
        break
      if len(tmp) == 0:
        print tmp
        break         
      size += len(tmp)
      self.buff += tmp
      print tmp
    file.close()
    if len(self.buff): 
     return self.buff

class textviewer(Module):
  """Show text file content
ex:cat /myfile.txt"""
  def __init__(self):
    Module.__init__(self, "textviewer", CAT)
    self.conf.addArgument({"name": "file",
                           "description": "Text file to display",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["HTML", "ASCII", "XML", "text"]})
    self.tags = "Viewers"
    self.flags = ["console", "gui"]
    self.icon = ":text"	
