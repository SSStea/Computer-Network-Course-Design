import sys, os
from PySide6.QtWidgets import QApplication, QPushButton, QComboBox, QLineEdit, QTableWidget, QHeaderView, QTableWidgetItem, QStackedWidget
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import QFile, QIODevice
from PySide6.QtGui import QIcon
from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP

ui_path = r"D:\0_Computer_Network_Course_Design\first_receiver\receiver.ui"
icon_path = r"D:\0_Computer_Network_Course_Design\first_receiver\icon.ico"
stop_receiving = threading.Event()
receiverPacket = ''

class MainWindow:
    def __init__(self):
        self.load_ui()
        self.bind_signals()

    def load_ui(self):
        loader = QUiLoader()
        file = QFile(ui_path)
        file.open(QIODevice.ReadOnly)
        self.window = loader.load(file)
        file.close()

        self.procotolCombo = self.window.findChild(QComboBox, "procotolCombo")
        self.filterEdit = self.window.findChild(QLineEdit, "filterEdit")
        self.startButtonWidget = self.window.findChild(QStackedWidget, "startButtonWidget")
        self.ALLStartButton = self.window.findChild(QPushButton, "ALLStartButton")
        self.EtherStartButton = self.window.findChild(QPushButton, "EtherStartButton")
        self.ARPStartButton = self.window.findChild(QPushButton, "ARPStartButton")
        self.IPStartButton = self.window.findChild(QPushButton, "IPStartButton")
        self.UDPStartButton = self.window.findChild(QPushButton, "UDPStartButton")
        self.TCPStartButton = self.window.findChild(QPushButton, "TCPStartButton")

        self.stopButton = self.window.findChild(QPushButton, "stopButton")
        self.clearButton = self.window.findChild(QPushButton, "clearButton")
        self.catchListWidget = self.window.findChild(QTableWidget, "catchListWidget")

        header = self.catchListWidget.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)

        self.catchListWidget.setColumnWidth(0, 100)
        self.catchListWidget.setColumnWidth(1, 160)
        self.catchListWidget.setColumnWidth(2, 160)
        self.catchListWidget.setColumnWidth(3, 80)
        self.catchListWidget.setColumnWidth(4, 80)
        self.catchListWidget.setColumnWidth(5, 350)

        self.procotolCombo.setCurrentIndex(0)
        self.startButtonWidget.setCurrentIndex(0)

        self.window.setWindowTitle("网络数据包抓包工具")
        self.window.setWindowIcon(QIcon(icon_path))

        self.window.setStyleSheet("""
            QWidget {
                background-color: #E6F7F7;
            }

            QLabel {
                color: #0F766E;
                font-weight: bold;
            }
            
            QGroupBox {
                border: 2px solid #16A085;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
                color: #0F766E;
                font-weight: bold;
            }
            
            /* ===== 输入框 / 下拉框（按你的控件名） ===== */
            #procotolCombo, #filterEdit {
                border: 1px solid #0F766E;
                border-radius: 5px;
                padding: 4px 8px;
                background-color: #FFFFFF;
                color: #1F2D3D;
            }
            
            #procotolCombo::drop-down {
                
                width: 20px;
            }
            
            #procotolCombo QAbstractItemView {
                background: white;
                selection-background-color: #0F766E;
                selection-color: white;
            }
            
            /* ===== 按钮通用样式 ===== */
            QPushButton {
                border: 1px solid #0F766E;
                border-radius: 6px;
                padding: 6px 14px;
                background-color: #FFFFFF;
                color: #0F766E;
                font-weight: bold;
            }
            
            QPushButton:hover {
                background-color: #D7F1F1;
            }
            
            QPushButton:pressed {
                background-color: #BFE8E8;
            }
            
            #stopButton {
                background-color: #E53935;
                color: white;
                border: none;
            }
            #stopButton:hover { background-color: #EF5350; }
            #stopButton:pressed { background-color: #C62828; }
            
            #clearButton {
                background-color: #009688;
                color: white;
                border: none;
            }
            #clearButton:hover { background-color: #26A69A; }
            #clearButton:pressed { background-color: #00796B; }
            
            /* ===== 表格（按你的 catchListWidget） ===== */
            #catchListWidget {
                background-color: #FFFFFF;
                gridline-color: #D0E5E5;
                border: 1px solid #D0E5E5;
                border-radius: 6px;
            }
            
            #catchListWidget::item {
                padding: 4px;
            }
            
            #catchListWidget::item:selected {
                background-color: #0F766E;
                color: white;
            }
            
            /* 表头 */
            #catchListWidget QHeaderView::section {
                background-color: #0F766E;
                color: white;
                padding: 6px;
                border: 1px solid #D0E5E5;
                font-weight: bold;
            }
            """)

    def bind_signals(self):
        self.ALLStartButton.clicked.connect(lambda: self.startButtonClicked("ALL"))
        self.EtherStartButton.clicked.connect(lambda: self.startButtonClicked("Ether"))
        self.ARPStartButton.clicked.connect(lambda: self.startButtonClicked("ARP"))
        self.IPStartButton.clicked.connect(lambda: self.startButtonClicked("IP"))
        self.UDPStartButton.clicked.connect(lambda: self.startButtonClicked("UDP"))
        self.TCPStartButton.clicked.connect(lambda: self.startButtonClicked("TCP"))

        self.stopButton.clicked.connect(self.stopButtonClicked)

        self.clearButton.clicked.connect(self.clearButtonClicked)

        self.procotolCombo.currentIndexChanged.connect(self.onChanged)

    def onChanged(self, index):
        self.startButtonWidget.setCurrentIndex(index)

    def startButtonClicked(self, type):
        stop_receiving.clear()



        t = threading.Thread(target=self.receivePacketThread, args=(type,))
        t.daemon = True # 设置守护线程
        t.start()

    def stopButtonClicked(self):
        stop_receiving.set()

    def clearButtonClicked(self):
        self.catchListWidget.setRowCount(0)

    def receivePacketThread(self, type):
        global receiverPacket
        # 开始接收时间点
        BPFfilter = self.filterEdit.text()
        while not stop_receiving.is_set():
            sniff(
                prn=lambda p: self.packetToShow(p, type),
                filter=BPFfilter if BPFfilter else None,
                store=False,
                timeout=1
            )

    def packetToShow(self, packet, type):
        if type == "Ether":
            if Ether not in packet:
                return
        elif type == "ARP":
            if ARP not in packet:
                return
        elif type == "IP":
            if IP not in packet:
                return
        elif type == "UDP":
            if UDP not in packet:
                return
        elif type == "TCP":
            if TCP not in packet:
                return

        length = len(packet) # 比 len(packet) 更稳

        # 按优先级判断协议层
        if TCP in packet:
            name = "TCP"
            src = packet[IP].src if IP in packet else ""
            dst = packet[IP].dst if IP in packet else ""
        elif UDP in packet:
            name = "UDP"
            src = packet[IP].src if IP in packet else ""
            dst = packet[IP].dst if IP in packet else ""
        elif ARP in packet:
            name = "ARP"
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
        elif IP in packet:
            name = "IP"
            src = packet[IP].src
            dst = packet[IP].dst
        elif Ether in packet:
            name = "Ether"
            src = packet[Ether].src
            dst = packet[Ether].dst
        else:
            src = ""
            dst = ""

        text = self.formatReceiveInfo(packet, name, src, dst)
        self.addCatchListRow(1, src, dst, name, str(length), text)

        print(dst)


    def formatReceiveInfo(self, pkt, procotolName, src, dst):
        lines = []
        lines.append(f"{procotolName} : {src} -> {dst}")
        lines.append("")

        return "\n".join(lines)

    def addCatchListRow(self, pos, src, dst, protocolName, length, info):
        table = self.catchListWidget
        row = table.rowCount()
        table.insertRow(row)

        now = datetime.now().strftime("%H:%M:%S")
        table.setItem(row, 0, QTableWidgetItem(now))
        table.setItem(row, 1, QTableWidgetItem(src))
        table.setItem(row, 2, QTableWidgetItem(dst))
        table.setItem(row, 3, QTableWidgetItem(protocolName))
        table.setItem(row, 4, QTableWidgetItem(length))
        table.setItem(row, 5, QTableWidgetItem(info))


app = QApplication(sys.argv)
w = MainWindow()
w.window.show()
sys.exit(app.exec())