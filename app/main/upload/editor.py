# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'main.ui'
#
# Created by: PyQt5 UI code generator 5.8.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QMainWindow, QAction, qApp, QApplication
from PyQt5.QtGui import QIcon

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.setGeometry(1000,600,1357,1050)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(2)
        sizePolicy.setVerticalStretch(2)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.textEdit_2 = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit_2.setGeometry(QtCore.QRect(680, 45, 671, 940))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.textEdit_2.setFont(font)
        self.textEdit_2.setObjectName("textEdit_2")
        self.textEdit = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit.setGeometry(QtCore.QRect(10, 45, 671, 940))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.textEdit.setFont(font)
        self.textEdit.setObjectName("textEdit")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1357, 23))
        self.menubar.setObjectName("menubar")

        self.toolbar = QtWidgets.QToolBar(MainWindow)
        self.toolbar.setGeometry(QtCore.QRect(0, 36, 1357, 46))
        self.toolbar.setObjectName("toolbar")

        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuTranslate = QtWidgets.QMenu(self.menubar)
        self.menuTranslate.setObjectName("menuTranslate")

        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.actionOpen = QAction(QIcon("open.png"), "&open", MainWindow)
        self.actionOpen.setObjectName("actionOpen")
        self.actionOpen.triggered.connect(MainWindow.open)

        self.actionExit = QAction(QIcon("exit.png"),"&exit",MainWindow)
        self.actionExit.setObjectName("actionExit")
        self.actionExit.triggered.connect(qApp.quit)

        self.actionTranslate = QtWidgets.QAction(MainWindow)
        self.actionTranslate.setObjectName("actionTranslate")

        self.actionTranslate_2 = QAction(QIcon("trans.png"), "&translate", MainWindow)
        self.actionTranslate_2.setObjectName("actionTranslate_2")
        self.actionTranslate_2.triggered.connect(MainWindow.tran)

        self.action_Save = QAction(QIcon("save.png"), "&save", MainWindow)
        self.action_Save.setObjectName("action_Save")
        self.action_Save.triggered.connect(MainWindow.save)

        self.menuFile.addAction(self.actionOpen)
        self.menuFile.addAction(self.action_Save)
        self.menuFile.addAction(self.actionExit)
        self.toolbar.addAction(self.actionOpen)
        self.toolbar.addAction(self.actionTranslate_2)
        self.toolbar.addAction(self.action_Save)
        self.toolbar.addAction(self.actionExit)
        self.menuTranslate.addAction(self.actionTranslate_2)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuTranslate.menuAction())

        self.retranslateUi(MainWindow)
        MainWindow.setWindowFlags(QtCore.Qt.WindowMinimizeButtonHint|QtCore.Qt.WindowCloseButtonHint)
        MainWindow.setFixedSize(MainWindow.width(), MainWindow.height())
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Translator"))
        MainWindow.setWindowIcon(QIcon('title.png'))
        self.menuFile.setTitle(_translate("MainWindow", "File"))
        self.menuTranslate.setTitle(_translate("MainWindow", "Translate"))
        self.actionOpen.setText(_translate("MainWindow", "Open"))
        self.actionExit.setText(_translate("MainWindow", "Exit"))
        self.actionTranslate.setText(_translate("MainWindow", "Save &As"))
        self.actionTranslate_2.setText(_translate("MainWindow", "Translate"))
        self.action_Save.setText(_translate("MainWindow", "&Save"))


