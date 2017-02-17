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
#  Jeremy MOUNIER <sja@digital-forensic.org>
# 
from PyQt4.QtGui import QFileDialog, QMessageBox, QInputDialog, QTableWidget, QTableWidgetItem, QDialog, QHBoxLayout, QPushButton, QVBoxLayout, QSplitter, QDialogButtonBox, QFormLayout, QWidget, QComboBox, QLabel, QPixmap
from PyQt4.QtCore import QString, Qt, SIGNAL, SLOT

from dff.api.taskmanager import *
from dff.api.taskmanager.taskmanager import *
from dff.api.loader import *
from dff.api.vfs import vfs
from dff.api.devices.devices import Devices

from dff.ui.gui.resources.ui_devicesdialog import Ui_DevicesDialog

class DevicesDialog(QDialog, Ui_DevicesDialog):
  def __init__(self, parent = None):
    QDialog.__init__(self)
    self.setupUi(self)
    self.selectedDevice = None
    self.listdevices = {}
    self.devices = Devices()

    for n in range(0, len(self.devices)):
      self.combodevice.addItem(self.devices[n].model())
      self.listdevices[n] = self.devices[n]

    self.setDeviceInformations(self.devices[0], True)
    self.selectedDevice = self.devices[0]
    self.connect(self.combodevice, SIGNAL("currentIndexChanged(int)"), self.deviceChanged) 
 
  def __del__(self):
      del self.devices

  def setDeviceInformations(self, device, init=False):
      self.blockdevice.setText(QString.fromUtf8(device.blockDevice()))
      self.model.setText(QString.fromUtf8(device.model()))
      self.serial.setText(QString.fromUtf8(device.serialNumber()))
      self.size.setText(str(device.size()))
      
  def deviceChanged(self, index):
    self.setDeviceInformations(self.listdevices[index])
    self.selectedDevice = self.listdevices[index]
