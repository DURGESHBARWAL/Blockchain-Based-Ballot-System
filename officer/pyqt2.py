import sys, socket, officer, address, threading, os
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon, QPixmap, QIntValidator
'''(QApplication, QCheckBox, QGridLayout, QGroupBox, QMainWindow, QLabel, QLineEdit,
        QMenu, QPushButton, QRadioButton, QVBoxLayout, QWidget)
'''

class Window(QWidget):
	def __init__(self, parent=None):
		super(Window, self).__init__(parent)
		self.grid = QGridLayout()
		self.grid.addWidget(self.createMyNode(), 0, 0)
		self.setLayout(self.grid)
		self.setWindowTitle("OFFICER")
		self.resize(400, 300)

	def createMyNode(self):
		groupBox = QGroupBox("YOUR NODE DETAILS")
		groupBox.setStyleSheet('''
				QGroupBox {
				border: 3px solid black;
				border-radius: 5px;
				}

				QGroupBox:title{
				subcontrol-origin: margin;
				subcontrol-position: top center;
				padding: 0 3px 0 3px;
				}
			''')
			
		l4 = QLabel()
		l4.setText("ENTER PASSWORD")
		e1 = self.password = QLineEdit()
		e1.setEchoMode(QLineEdit.Password)
		e1.setMaxLength(15)
		hpass = QHBoxLayout()
		hpass.addWidget(l4,0,Qt.AlignCenter)
		hpass.addWidget(e1,0,Qt.AlignCenter)		
	
		l2 = QLabel()
		self.ip = getIp()
		l2.setText("YOUR IP: {}".format(self.ip))
		l3 = QLabel()
		l3.setText("ENTER DESIRED PORT: ")
		self.in_port = QLineEdit()
		self.intValidator = QIntValidator()
		self.in_port.setValidator(self.intValidator)
		self.in_port.setMaxLength(5)
		
		port_group = QHBoxLayout()
		port_group.addWidget(l3, 0, Qt.AlignCenter)
		port_group.addWidget(self.in_port, 0, Qt.AlignCenter)

		b1 = QPushButton('CONNECT TO HOST', self)
		self.b1 = b1
		self.b1.setEnabled(False) 
		b1.setToolTip('CLICK TO ESTABLISH CONNECTION')
		b1.setStyleSheet("""
			QToolTip {
			border: 1px solid #76797C;
			background-color: rgb(90, 102, 117);
			color: white;	
			border-radius: 5px;
			padding: 2px;
			opacity: 0;
			}
			""")
		b1.clicked.connect(self.socketCreation)
	
		l4 = self.l4 = QLabel()
		l4.setText("ENTER HOST ADDRESS")
		e1 = self.e1 = QLineEdit()
		e1.setMaxLength(15)
		hbox = QHBoxLayout()
		hbox.addWidget(l4,0,Qt.AlignCenter)
		hbox.addWidget(e1,0,Qt.AlignCenter)
		l5 = self.l5 = QLabel()
		l5.setText("ENTER HOST PORT")
		
		f = lambda x: x.setEnabled(False)
		
		f(l4)
		f(e1)
		f(l5)
		
		e2 = self.e2 = QLineEdit()
		e2.setValidator(self.intValidator)
		
		f(e2)
		
		e2.setMaxLength(5)
		hbox2 = QHBoxLayout()
		hbox2.addWidget(l5,0,Qt.AlignCenter)
		hbox2.addWidget(e2,0,Qt.AlignCenter)

		vbox = QBoxLayout(2,None)
		vbox.addLayout(hpass, 0)
		vbox.addSpacing(6)
		vbox.addWidget(l2,0,Qt.AlignCenter)
		self.joinNetwork = QPushButton("JOIN NETWORK")
		self.joinNetwork.clicked.connect(self.join_Network)
		self.okboot = QPushButton("ESTABLISH CONNECTION")
		self.okboot.clicked.connect(self.socketCreation)
		
		vbox.addLayout(port_group,0)
		vbox.addWidget(self.okboot,0)		
		vbox.addWidget(self.joinNetwork)
		vbox.addLayout(hbox,0)
		vbox.addLayout(hbox2,0)
		vbox.addWidget(b1,0,Qt.AlignCenter)
	
		groupBox.setLayout(vbox)
		return groupBox
		
	def join_Network(self):
		self.e1.setEnabled(True)
		self.e2.setEnabled(True)
		self.l4.setEnabled(True)
		self.l5.setEnabled(True)
		self.b1.setEnabled(True)
	
	def viewChainUsingFirefox(self):
		self.conn.writeChain()
		try:
			f = open('chain.json', 'r')
			f.close()
			os.system('firefox chain.json')
		except:
			pass
		
	def getBlockChain(self):
		groupBox = QGroupBox("GET BLOCK-CHAIN")
		groupBox.setStyleSheet('''
		QGroupBox {
			border: 3px solid black;
			border-radius: 5px;
			}

			QGroupBox:title{
			subcontrol-origin: margin;
			subcontrol-position: top center;
			padding: 0 3px 0 3px;
			}
		''')
		vbox = QVBoxLayout()
		l = QLabel()
		l.setText('YOUR IP/PORT: {}/{}'.format(self.ip, self.port))
		vbox.addWidget(l, 0, Qt.AlignCenter)
		qbox = QHBoxLayout()
		
		self.browseChain = QPushButton("VIEW BLOCK-CHAIN")
		self.browseChain.clicked.connect(self.viewChainUsingFirefox)
		
		qbox.addWidget(self.browseChain, 0, Qt.AlignCenter)
		
		vbox.addLayout(qbox, 0)
		
		l = QPushButton('SHUTDOWN SYSTEM')
		l.clicked.connect(self.close)
		vbox.addWidget(l, 0, Qt.AlignCenter)
		
		groupBox.setLayout(vbox)
		
		return groupBox
		
	def clicked(self,enabled):
		if enabled:
			print("JAckass")
	
	def __refreshNeighbours(self):
		qbox = self.qbox
		for i in reversed(range(qbox.count())): 
			qbox.itemAt(i).widget().setParent(None)
			
		refresh_btn = QPushButton("REFRESH")
		refresh_btn.clicked.connect(self.__refreshNeighbours)
			
		l1 = QLabel()
		pixmap = QPixmap('//home//kingzthefirst//Desktop//project//index.png')
		#pixmap2 = pixmap.scaled(64, 64, QtCore.Qt.KeepAspectRatio)
		#pixmap2 = pixmap.scaledToHeight(44)
		pixmap2 = pixmap.scaled(50,50,2)
		l1.setPixmap(pixmap2)
		qbox.addWidget(l1,0,Qt.AlignCenter)
		
		l1 = QLabel()
		a, b = self.conn.getTurnout()
		l1.setText('TOTAL VOTE CASTED: {}%'.format((a / b) * 100))
		qbox.addWidget(l1,0,Qt.AlignCenter)		
		
		for k, v in self.conn.getNeighbours().items():
			l2 = QLabel()
			l2.setText("NEIGHBOUR IP/PORT: {}/{}".format(k[0], k[1]))
			qbox.addWidget(l2,0,Qt.AlignCenter)
			
		qbox.addWidget(refresh_btn,0,Qt.AlignCenter)
		
	def neighbourNodes(self):
		groupBox = self.groupBox = QGroupBox('EXTRA DETAILS')
		groupBox.setStyleSheet('''
		QGroupBox {
			border: 3px solid black;
			border-radius: 5px;
			}

			QGroupBox:title{
			subcontrol-origin: margin;
			subcontrol-position: top center;
			padding: 0 3px 0 3px;
			}
		''')
		
		self.qbox = QBoxLayout(2, None)
		
		self.__refreshNeighbours()
		
		groupBox.setLayout(self.qbox)
		
		return groupBox
			
	def socketCreation(self):
		self.port = int(self.in_port.text()) if len(self.in_port.text()) != 0 else 0
			
		s = self.password.text()
		
		if len(s) < 8:
			errorMessage = QMessageBox.critical(self, 'PASSWORD ERROR', 'Password must be of atleast 8 characters', QMessageBox.Retry, QMessageBox.Retry)
			return
		
		try:
			# get another input for password
			if self.e1.isEnabled():
				host_ip, host_port = self.e1.text(), self.e2.text()
				self.conn = officer.Node(s, address.Address(self.ip, self.port), address.Address(host_ip, int(host_port)))
			else:
				self.conn = officer.Node(s, address.Address(self.ip, self.port))
			self.conn.toggleMiner()
		except Exception as e:
			# Open a window for displaying connection error
			# print('Connection Error: {}'.format(e))
			errorMessage = QMessageBox.critical(self, 'CONNECTION ERROR', str(e), QMessageBox.Retry, QMessageBox.Retry)
			return
		for i in reversed(range(self.grid.count())): 
			self.grid.itemAt(i).widget().setParent(None)
		
		self.resize(800, 300)
		self.grid.addWidget(self.neighbourNodes(), 0, 1)
		self.grid.addWidget(self.getBlockChain(), 0, 2)
	

def getIp():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		s.connect(('8.8.8.8', 80))
		return s.getsockname()[0]
	except socket.error:
		return '127.0.0.1'


if __name__ == '__main__':
	app = QApplication(sys.argv)
	ob = Window()
	ob.show()
	sys.exit(app.exec_())
