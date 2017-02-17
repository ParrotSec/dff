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

__dff_module_viewerimage_version__ = "1.0.0"

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import Qt, QSize, QString, SIGNAL, QThread
from PyQt4.QtGui import QPixmap, QImage, QPushButton, QLabel, QWidget, QHBoxLayout, QVBoxLayout, QScrollArea, QIcon, QMatrix, QToolBar, QAction, QSizePolicy, QTabWidget, QTableWidget, QTableWidgetItem, QAbstractItemView, QLineEdit
from PyQt4.QtGui import QImageReader, QMovie, QSizePolicy

from dff.api.vfs import vfs 
from dff.api.module.module import Module 
from dff.api.module.script import Script
from dff.api.types.libtypes import Argument, typeId

from dff.api.gui.thumbnail import Thumbnailer

class ThumbnailVideoView(QWidget, Script):
  def __init__(self):
    Script.__init__(self, "thumbnailvideo")
    self.icon = None
    self.vfs = vfs.vfs()

  def start(self, args):
    try :
      self.preview = args["preview"].value()
    except IndexError:
      self.preview = False
    try:
      self.node = args["file"].value()
    except KeyError:
      pass

  def g_display(self):
    QWidget.__init__(self)
    self.hlayout = QHBoxLayout()
    self.scrollArea = QScrollArea()
    self.scrollWidget = QWidget()
    self.hhlayout = QHBoxLayout()
    self.scrollWidget.setLayout(self.hhlayout)
    self.setLayout(self.hlayout)
    self.thumbnailer = Thumbnailer()
    self.connect(self.thumbnailer, SIGNAL("ThumbnailUpdate"), self.updateThumbnail)

    pixmap = self.thumbnailer.generate(self.node, iconSize = 256, frames = 10)
    if pixmap:
	self.updateThumbnail(self.node, pixmap)


  def updateThumbnail(self, node, pixmap):
     if pixmap:
       label = QLabel()
       label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
       label.setWordWrap(True)
       label.setPixmap(pixmap)
     else:
       label = QLabel("Can't render, video is corrupted.")
       label.setAlignment(Qt.AlignCenter)
     self.hhlayout.addWidget(label)
     self.scrollArea.setWidget(self.scrollWidget)
     self.hlayout.addWidget(self.scrollArea)
     self.thumbnailer.unregister()

  def updateWidget(self):
     pass

class videothumbnailviewer(Module):
  """Create thumbnail from video files."""
  def __init__(self):
    Module.__init__(self, "thumbnailvideo", ThumbnailVideoView)
    self.conf.addArgument({"name": "file",
                           "description": "Picture file to display",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "preview",
			   "description": "Preview mode",
			   "input": Argument.Empty})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["avi", "video"]})
    self.tags = "Viewers"
    self.icon = ":movie"
