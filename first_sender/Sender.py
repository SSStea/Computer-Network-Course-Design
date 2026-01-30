import sys, os
from datetime import datetime
from PySide6.QtWidgets import QApplication, QStackedWidget, QRadioButton, QPushButton, QLineEdit, QTextEdit, \
    QTableWidget, QTableWidgetItem, QMessageBox, QDialog
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import QFile, QIODevice
from PySide6.QtGui import QIcon
from scapy.all import *
from scapy.layers.inet import in4_chksum
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP
import re
import ipaddress

ui_path = r"D:\0_Computer_Network_Course_Design\first_sender\test.ui"
icon_path = r"D:\0_Computer_Network_Course_Design\first_sender\icon.ico"
_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}([-:]))(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}$")


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

        self.parameterSet = self.window.findChild(QStackedWidget, "parameterSet")
        self.EtherradioButton = self.window.findChild(QRadioButton, "EtherradioButton")
        self.ARPradioButton = self.window.findChild(QRadioButton, "ARPradioButton")
        self.IPradioButton = self.window.findChild(QRadioButton, "IPradioButton")
        self.TCPradioButton = self.window.findChild(QRadioButton, "TCPradioButton")
        self.UDPradioButton = self.window.findChild(QRadioButton, "UDPradioButton")

        self.sendButtonSet = self.window.findChild(QStackedWidget, "sendButtonSet")
        self.EtherSendButton = self.window.findChild(QPushButton, "EtherSendButton")
        self.ARPSendButton = self.window.findChild(QPushButton, "ARPSendButton")
        self.IPSendButton = self.window.findChild(QPushButton, "IPSendButton")
        self.TCPSendButton = self.window.findChild(QPushButton, "TCPSendButton")
        self.UDPSendButton = self.window.findChild(QPushButton, "UDPSendButton")

        self.parameterSet.setCurrentIndex(0)
        self.sendButtonSet.setCurrentIndex(0)
        self.EtherradioButton.setChecked(True)

        self.EtherdstMACEdit = self.window.findChild(QLineEdit, "EtherdstMACEdit")
        self.EthersrcMACEdit = self.window.findChild(QLineEdit, "EthersrcMACEdit")
        self.EtherpayloadEdit = self.window.findChild(QLineEdit, "EtherpayloadEdit")
        self.EthersendCountEdit = self.window.findChild(QLineEdit, "EthersendCountEdit")
        self.EtherdstMACEdit.setText("FF:FF:FF:FF:FF:FF")
        self.EthersrcMACEdit.setText("00:00:00:00:00:00")
        self.EtherpayloadEdit.setText("12345678")
        self.EthersendCountEdit.setText("10")

        self.dstMACEdit = self.window.findChild(QLineEdit, "dstMACEdit")
        self.ARPdstMACEdit = self.window.findChild(QLineEdit, "ARPdstMACEdit")
        self.ARPdstIPEdit = self.window.findChild(QLineEdit, "ARPdstIPEdit")
        self.ARPsrcMACEdit = self.window.findChild(QLineEdit, "ARPsrcMACEdit")
        self.ARPsrcIPEdit = self.window.findChild(QLineEdit, "ARPsrcIPEdit")
        self.ARPpayloadEdit = self.window.findChild(QLineEdit, "ARPpayloadEdit")
        self.ARPsendCountEdit = self.window.findChild(QLineEdit, "ARPsendCountEdit")
        self.dstMACEdit.setText("FF:FF:FF:FF:FF:FF")
        self.ARPdstMACEdit.setText("2c:56:dc:d3:ab:db")
        self.ARPdstIPEdit.setText("192.168.31.247")
        self.ARPsrcMACEdit.setText("08:00:27:97:d1:f5")
        self.ARPsrcIPEdit.setText("192.168.31.1")
        self.ARPpayloadEdit.setText("aaaaaaaa")
        self.ARPsendCountEdit.setText("10")

        self.IPdstIPEdit = self.window.findChild(QLineEdit, "IPdstIPEdit")
        self.IPsrcIPEdit = self.window.findChild(QLineEdit, "IPsrcIPEdit")
        self.IPpayloadEdit = self.window.findChild(QLineEdit, "IPpayloadEdit")
        self.IPsendCountEdit = self.window.findChild(QLineEdit, "IPsendCountEdit")
        self.IPdstIPEdit.setText("192.168.31.247")
        self.IPsrcIPEdit.setText("192.168.31.1")
        self.IPpayloadEdit.setText("aaaaaaaa")
        self.IPsendCountEdit.setText("10")

        self.UDPdstIPEdit = self.window.findChild(QLineEdit, "UDPdstIPEdit")
        self.UDPsrcIPEdit = self.window.findChild(QLineEdit, "UDPsrcIPEdit")
        self.UDPdstPortEdit = self.window.findChild(QLineEdit, "UDPdstPortEdit")
        self.UDPsrcPortEdit = self.window.findChild(QLineEdit, "UDPsrcPortEdit")
        self.UDPpayloadEdit = self.window.findChild(QLineEdit, "UDPpayloadEdit")
        self.UDPsendCountEdit = self.window.findChild(QLineEdit, "UDPsendCountEdit")
        self.UDPdstIPEdit.setText("192.168.31.247")
        self.UDPsrcIPEdit.setText("192.168.31.1")
        self.UDPdstPortEdit.setText("8080")
        self.UDPsrcPortEdit.setText("9090")
        self.UDPpayloadEdit.setText("aaaaaaaa")
        self.UDPsendCountEdit.setText("10")

        self.TCPdstIPEdit = self.window.findChild(QLineEdit, "TCPdstIPEdit")
        self.TCPsrcIPEdit = self.window.findChild(QLineEdit, "TCPsrcIPEdit")
        self.TCPdstPortEdit = self.window.findChild(QLineEdit, "TCPdstPortEdit")
        self.TCPsrcPortEdit = self.window.findChild(QLineEdit, "TCPsrcPortEdit")
        self.TCPpayloadEdit = self.window.findChild(QLineEdit, "TCPpayloadEdit")
        self.TCPsendCountEdit = self.window.findChild(QLineEdit, "TCPsendCountEdit")
        self.TCPdstIPEdit.setText("192.168.31.247")
        self.TCPsrcIPEdit.setText("192.168.31.1")
        self.TCPdstPortEdit.setText("8080")
        self.TCPsrcPortEdit.setText("9090")
        self.TCPpayloadEdit.setText("aaaaaaaa")
        self.TCPsendCountEdit.setText("10")

        self.sendResultEdit = self.window.findChild(QTextEdit, "sendResultEdit")

        self.sendHistoryWidget = self.window.findChild(QTableWidget, "sendHistoryWidget")

        self.window.setWindowTitle("网络数据包发送工具")
        self.window.setWindowIcon(QIcon(icon_path))

        self.window.setStyleSheet("""
            QWidget {
                background-color: #FFF7E6;
            }

            QGroupBox {
                border: 2px solid #FFA940;
            }

            QGroupBox::title {
                color: #FA8C16;
            }

            QPushButton {
                background-color: #FA8C16;
            }

            QPushButton:hover {
                background-color: #FF9C2A;
            }

            QTableWidget {
                background-color: white;
            }

            QHeaderView::section {
                background-color: #FA8C16;
                color: white;
            }
            
            QRadioButton::indicator:unchecked {
                border: 2px solid #FA8C16;
                border-radius: 8px;
                background-color: white;
            }

            QRadioButton::indicator:checked {
                border: 2px solid #FA8C16;
                border-radius: 8px;
                background-color: #FA8C16;
            }
            
            QLabel {
                color: #FA8C16;
            }
            """)

    def bind_signals(self):
        #self.sendButton.clicked.connect(self.sendButtonClicked)
        self.EtherradioButton.toggled.connect(lambda checked: checked and self.parameterSet.setCurrentIndex(0))
        self.IPradioButton.toggled.connect(lambda checked: checked and self.parameterSet.setCurrentIndex(1))
        self.UDPradioButton.toggled.connect(lambda checked: checked and self.parameterSet.setCurrentIndex(2))
        self.TCPradioButton.toggled.connect(lambda checked: checked and self.parameterSet.setCurrentIndex(3))
        self.ARPradioButton.toggled.connect(lambda checked: checked and self.parameterSet.setCurrentIndex(4))

        self.EtherradioButton.toggled.connect(lambda checked: checked and self.sendButtonSet.setCurrentIndex(0))
        self.ARPradioButton.toggled.connect(lambda checked: checked and self.sendButtonSet.setCurrentIndex(4))
        self.IPradioButton.toggled.connect(lambda checked: checked and self.sendButtonSet.setCurrentIndex(1))
        self.TCPradioButton.toggled.connect(lambda checked: checked and self.sendButtonSet.setCurrentIndex(3))
        self.UDPradioButton.toggled.connect(lambda checked: checked and self.sendButtonSet.setCurrentIndex(2))

        self.EtherSendButton.clicked.connect(self.EtherSendButtonClicked)
        self.ARPSendButton.clicked.connect(self.ARPSendButtonClicked)
        self.IPSendButton.clicked.connect(self.IPSendButtonClicked)
        self.TCPSendButton.clicked.connect(self.TCPSendButtonClicked)
        self.UDPSendButton.clicked.connect(self.UDPSendButtonClicked)

    def EtherSendButtonClicked(self):
        dstMAC = self.EtherdstMACEdit.text()
        srcMAC = self.EthersrcMACEdit.text()
        EtherPayload = self.EtherpayloadEdit.text()
        EtherSendCount = int(self.EthersendCountEdit.text().strip())

        if not self.isValidMac(dstMAC):
            QMessageBox.critical(self.window, "输入错误", "目的MAC地址格式不合法\n示例：FF:FF:FF:FF:FF:FF")
            self.dstMACEdit.setFocus()
            return

        if not self.isValidMac(srcMAC):
            QMessageBox.critical(self.window, "输入错误", "源MAC地址格式不合法\n示例：FF:FF:FF:FF:FF:FF")
            self.dstMACEdit.setFocus()
            return

        ether = Ether(dst = dstMAC, src = srcMAC) / EtherPayload
        print(ether.show())

        for i in range(EtherSendCount):
            sendp(ether)

        text = self.formatSendResult(ether, "MAC帧", dstMAC)
        self.sendResultEdit.setPlainText(text)
        self.addHistoryRow("MAC帧", dstMAC, "successful", self.EthersendCountEdit.text())

    def ARPSendButtonClicked(self):
        dstMAC = self.dstMACEdit.text()
        ARPdstMAC = self.ARPdstMACEdit.text()
        ARPdstIP = self.ARPdstIPEdit.text()
        ARPsrcMAC = self.ARPsrcMACEdit.text()
        ARPsrcIP = self.ARPsrcIPEdit.text()
        ARPpayload = self.ARPpayloadEdit.text()
        ARPsendCount = int(self.ARPsendCountEdit.text().strip())

        if not self.isValidMac(dstMAC):
            QMessageBox.critical(self.window, "输入错误", "目的MAC地址格式不合法\n示例：FF:FF:FF:FF:FF:FF")
            self.dstMACEdit.setFocus()
            return
        if not self.isValidMac(ARPdstMAC):
            QMessageBox.critical(self.window, "输入错误", "ARP目的MAC地址格式不合法\n示例：FF:FF:FF:FF:FF:FF")
            self.dstMACEdit.setFocus()
            return
        if not self.isValidMac(ARPsrcMAC):
            QMessageBox.critical(self.window, "输入错误", "ARP源MAC地址格式不合法\n示例：FF:FF:FF:FF:FF:FF")
            self.dstMACEdit.setFocus()
            return
        if not self.isValidIp(ARPdstIP):
            QMessageBox.critical(self.window, "输入错误", "ARP目的IP地址格式不合法\n示例：192.168.31.247")
            self.IPdstIPEdit.setFocus()
            return
        if not self.isValidIp(ARPsrcIP):
            QMessageBox.critical(self.window, "输入错误", "ARP源IP地址格式不合法\n示例：192.168.31.247")
            self.IPdstIPEdit.setFocus()
            return

        arp = ARP(op = 'is-at', hwsrc = ARPsrcMAC, psrc = ARPsrcIP, hwdst = ARPdstMAC, pdst = ARPdstIP)
        frame = Ether(dst=dstMAC) / arp / Raw(ARPpayload.encode(errors="ignore"))

        print(frame.show())

        for i in range(ARPsendCount):
            sendp(frame, verbose=False)

        text = self.formatSendResult(frame, "ARP包", ARPdstIP)
        self.sendResultEdit.setPlainText(text)
        self.addHistoryRow("ARP包", ARPdstIP, "successful", self.ARPsendCountEdit.text())

    def IPSendButtonClicked(self):
        IPdstIP = self.IPdstIPEdit.text()
        IPsrcIP = self.IPsrcIPEdit.text()
        IPpayload = self.IPpayloadEdit.text()
        IPsendCount = int(self.IPsendCountEdit.text().strip())

        if not self.isValidIp(IPdstIP):
            QMessageBox.critical(self.window, "输入错误", "IP目的IP地址格式不合法\n示例：192.168.31.247")
            self.IPdstIPEdit.setFocus()
            return
        if not self.isValidIp(IPsrcIP):
            QMessageBox.critical(self.window, "输入错误", "IP源IP地址格式不合法\n示例：192.168.31.247")
            self.IPdstIPEdit.setFocus()
            return

        IPPacketPayload = IP(dst=IPdstIP, src=IPsrcIP) / Raw(IPpayload.encode(errors="ignore"))

        x = raw(IPPacketPayload)
        ipRaw = IP(x)

        checksumScapy = ipRaw[IP].chksum
        print("scapy计算的IP首部校验和：%04x (%s)" % (checksumScapy, str(checksumScapy)))

        def IPheadchecksum(IP_head: bytes) -> int:
            checksum = 0
            headlen = len(IP_head)
            if headlen % 2 == 1:
                IP_head += b"\0"

            s = 0
            while s < headlen:
                temp = struct.unpack('!H', IP_head[s:s + 2])[0]
                checksum += temp
                s += 2

            checksum = (checksum >> 16) + (checksum & 0xffff)
            checksum = checksum + (checksum >> 16)
            return (~checksum) & 0xffff

        ihl = ipRaw[IP].ihl
        head_bytes = bytearray(x[:ihl * 4])
        head_bytes[10] = 0
        head_bytes[11] = 0

        checksumChangedSelf = IPheadchecksum(bytes(head_bytes))
        print("手工计算的IP首部校验和：%04x (%s)" % (checksumChangedSelf, str(checksumChangedSelf)))

        if checksumScapy == checksumChangedSelf:
            print("校验和对比：正确")
        else:
            print("校验和对比：不正确")

        IPPacketPayload[IP].chksum = checksumChangedSelf

        ether = Ether()
        frame = ether / IPPacketPayload

        print(frame.show())

        for i in range(IPsendCount):
            scapy.all.sendp(frame)

        text = self.formatSendResult(frame, "IP包", IPdstIP)
        text += (
            f"\n\n校验和验证：\n"
            f"Scapy: 0x{checksumScapy:04x}\n"
            f"Self : 0x{checksumChangedSelf:04x}\n"
            f"结果 : {'正确' if checksumScapy == checksumChangedSelf else '不正确'}\n"
        )
        self.sendResultEdit.setPlainText(text)
        self.addHistoryRow("IP包", IPdstIP, "successful", self.IPsendCountEdit.text())

    def TCPSendButtonClicked(self):
        TCPdstIP = self.TCPdstIPEdit.text()
        TCPsrcIP = self.TCPsrcIPEdit.text()
        TCPdstPort = int(self.TCPdstPortEdit.text().strip())
        TCPsrcPort = int(self.TCPsrcPortEdit.text().strip())
        TCPpayload = self.TCPpayloadEdit.text()
        TCPsendCount = int(self.TCPsendCountEdit.text().strip())

        if not self.isValidIp(TCPdstIP):
            QMessageBox.critical(self.window, "输入错误", "TCP目的IP地址格式不合法\n示例：192.168.31.247")
            self.IPdstIPEdit.setFocus()
            return
        if not self.isValidIp(TCPsrcIP):
            QMessageBox.critical(self.window, "输入错误", "TCP源IP地址格式不合法\n示例：192.168.31.247")
            self.IPdstIPEdit.setFocus()
            return

        TCPPacketPayload = IP(dst=TCPdstIP, src=TCPsrcIP) / TCP(dport=TCPdstPort, sport=TCPsrcPort) / Raw(TCPpayload.encode(errors="ignore"))

        scapyPacket = IP(raw(TCPPacketPayload))
        scapyChecksum = scapyPacket[TCP].chksum
        print('添加负载数据后scapy计算的校验和是：%04x(%s)' % (scapyChecksum, str(scapyChecksum)))

        TCPPacketPayload[TCP].chksum = 0
        packet_raw = raw(TCPPacketPayload)
        tcp_raw = packet_raw[20:]
        chksum = in4_chksum(socket.IPPROTO_TCP, TCPPacketPayload[IP], tcp_raw)

        print("验证计算TCP首部校验和：%04x(%s)" % (scapyChecksum, str(scapyChecksum)))
        if (scapyChecksum == chksum):
            print("正确")
        else:
            print('不正确')
        ether = Ether()
        frame = ether / TCPPacketPayload
        print(frame.show())

        for i in range(int(TCPsendCount)):
            sendp(ether / scapyPacket)

        text = self.formatSendResult(frame, "TCP包", TCPdstIP)
        self.sendResultEdit.setPlainText(text)
        self.addHistoryRow("TCP包", TCPdstIP, "successful", self.TCPsendCountEdit.text())

    def UDPSendButtonClicked(self):
        UDPdstIP = self.UDPdstIPEdit.text()
        UDPsrcIP = self.UDPsrcIPEdit.text()
        UDPdstPort = int(self.UDPdstPortEdit.text().strip())
        UDPsrcPort = int(self.UDPsrcPortEdit.text().strip())
        UDPpayload = self.UDPpayloadEdit.text()
        UDPsendCount = int(self.UDPsendCountEdit.text().strip())

        if not self.isValidIp(UDPdstIP):
            QMessageBox.critical(self.window, "输入错误", "UDP目的IP地址格式不合法\n示例：192.168.31.247")
            self.IPdstIPEdit.setFocus()
            return
        if not self.isValidIp(UDPsrcIP):
            QMessageBox.critical(self.window, "输入错误", "UDP源IP地址格式不合法\n示例：192.168.31.247")
            self.IPdstIPEdit.setFocus()
            return

        UDPPacketPayload = IP(dst=UDPdstIP, src=UDPsrcIP) / UDP(dport=UDPdstPort, sport=UDPsrcPort) / Raw(UDPpayload.encode(errors="ignore"))
        scapyPacket = IP(raw(UDPPacketPayload))
        scapyChecksum = scapyPacket[UDP].chksum
        print('添加负载数据后scapy计算的校验和是：%04x(%s)' % (scapyChecksum, str(scapyChecksum)))

        ether = Ether()
        frame = ether / UDPPacketPayload
        print(frame.show())

        for i in range(int(UDPsendCount)):
            sendp(ether / scapyPacket)

        text = self.formatSendResult(frame, "UDP包", UDPdstIP)
        self.sendResultEdit.setPlainText(text)
        self.addHistoryRow("UDP包", UDPdstIP, "successful", self.UDPsendCountEdit.text())

    def formatSendResult(self, pkt, procotolName, dst):
        ts = datetime.now().strftime("%H:%M:%S")
        lines = []
        lines.append(f"发送 {procotolName} 到 {dst}:")
        lines.append("")
        lines.append(f"数据包摘要：{pkt.summary()}")
        lines.append("")
        lines.append("详细信息：")

        # Ether
        if Ether in pkt:
            lines.append(f"源MAC: {pkt[Ether].src}")
            lines.append(f"目的MAC: {pkt[Ether].dst}")

        # ARP
        if ARP in pkt:
            a = pkt[ARP]
            lines.append(f"ARP op: {a.op}")
            lines.append(f"源IP: {a.psrc}")
            lines.append(f"目的IP: {a.pdst}")
            lines.append(f"源MAC: {a.hwsrc}")
            lines.append(f"目的MAC: {a.hwdst}")

        # IP
        if IP in pkt:
            ip = pkt[IP]
            lines.append(f"源IP: {ip.src}")
            lines.append(f"目的IP: {ip.dst}")
            lines.append(f"协议: {ip.proto}")
            lines.append(f"TTL: {ip.ttl}")

        # TCP/UDP ports
        if TCP in pkt:
            t = pkt[TCP]
            lines.append(f"源端口: {t.sport}")
            lines.append(f"目的端口: {t.dport}")
            lines.append(f"Flags: {t.flags}")
        elif UDP in pkt:
            u = pkt[UDP]
            lines.append(f"源端口: {u.sport}")
            lines.append(f"目的端口: {u.dport}")

        return "\n".join(lines)

    def addHistoryRow(self, protocolName, dst, status, count):
        table = self.sendHistoryWidget
        row = table.rowCount()
        table.insertRow(row)

        now = datetime.now().strftime("%H:%M:%S")
        table.setItem(row, 0, QTableWidgetItem(now))
        table.setItem(row, 1, QTableWidgetItem(protocolName))
        table.setItem(row, 2, QTableWidgetItem(dst))
        table.setItem(row, 3, QTableWidgetItem(status))
        table.setItem(row, 4, QTableWidgetItem(count))

    def isValidMac(self, MAC):
        s = (MAC or "").strip()
        return bool(_MAC_RE.match(s))

    def isValidIp(self, IP):
        s = (IP or "").strip()
        try:
            return ipaddress.ip_address(s).version == 4
        except ValueError:
            return False

app = QApplication(sys.argv)
w = MainWindow()
w.window.show()
sys.exit(app.exec())

