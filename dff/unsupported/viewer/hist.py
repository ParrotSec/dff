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
#  Frederic Baguelin <fba@digital-forensic.org>
# 

__dff_module_player_version__ = "1.0.0"

from PyQt4 import QtGui, QtCore

from matplotlib.backends.backend_qt4agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from matplotlib.text import Text

from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.types.libtypes import Argument, typeId

class HIST(QtGui.QWidget, Script):
  def __init__(self):
    Script.__init__(self, "file histogram")
    self.freq = [0 for i in xrange(0, 256)]
    self.xcount = [i for i in xrange(0, 256)]

  def start(self, args):
    self.stateinfo = "counting byte occurences 0%"
    try:
      self.node = args["file"].value()
      f = self.node.open()
      buff = f.read(10*1024*1024)
      size = self.node.size()
      read = 0
      while len(buff) > 0:
        for c in buff:
          self.freq[ord(c)] += 1
          read += 1
          self.stateinfo = "counting byte occurences " + str(float(read*100/size)) + "%"
        buff = f.read(10*1024*1024)
      f.close()
    except:
      pass

  def updateWidget(self):
    pass


  def g_display(self):
    QtGui.QWidget.__init__(self)
    self.oldtxt = None
    self.fig = Figure(figsize=(5, 5), dpi=100)
    self.canvas = FigureCanvas(self.fig)
    self.canvas.setParent(self)
    self.canvas.setSizePolicy(QtGui.QSizePolicy.Expanding,
                              QtGui.QSizePolicy.Expanding)
    self.canvas.updateGeometry()
    self.canvas.mpl_connect('motion_notify_event', self.on_motion)
    self.ax = self.fig.add_axes([0.2,0.2,0.5,0.7])
    self.ax.set_xlabel("Byte")
    self.ax.set_ylabel("Frequency")
    self.ax.set_title("Byte Distribution of file \"" + self.node.name() + "\"")
    self.ax.set_xlim(0, 256)
    self.rects = self.ax.bar(self.xcount, self.freq, width=1, color='g', edgecolor='k')
    self.ax.set_xticks([i for i in xrange(0, 256, 10)])
    for label in self.ax.xaxis.get_ticklabels():
      label.set_color('black')
      label.set_rotation(45)
      label.set_fontsize(12)
    for label in self.ax.yaxis.get_ticklabels():
      label.set_color('black')
      label.set_rotation(-45)
      label.set_fontsize(12)
    self.ax.grid(True)
    self.ax.autoscale(enable=True, axis='y')
    self.txt = self.fig.text(0, 0.1, '')
    self.orect = None
    vbox = QtGui.QVBoxLayout(self)
    vbox.addWidget(self.canvas)

  def on_motion(self, event):
      if event.xdata != None:
          x = int(event.xdata)
          rect = self.rects[x]     
          if self.orect != None and self.orect != rect:
              self.orect.set_facecolor('g')
          rect.set_facecolor('b')
          self.orect = rect
          self.txt.set_text("byte: " + hex(x) + " -- frequency: " + str(self.freq[x]))
          self.canvas.draw()
     
  def setupUi(self):
    pass


class hist(Module):
  def __init__(self):
   """Histogram diplay"""
   Module.__init__(self, "hist", HIST)
   self.conf.addArgument({"name": "file",
                          "description": "input file used to generate histogram",
                          "input": Argument.Required|Argument.Single|typeId.Node})
   self.tags = "Viewers"
