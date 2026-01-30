import sys, os, json, socket
from PySide6.QtWidgets import QApplication, QStackedWidget, QPushButton, QLineEdit, QMessageBox
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import QFile, QIODevice
from PySide6.QtGui import QIcon
import socket

ui_path = r"D:\0_Computer_Network_Course_Design\second_client\client.ui"
icon_path = r"D:\0_Computer_Network_Course_Design\second_client\icon.ico"

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

def send_req(req: dict) -> dict:
    """最简单：一次连接发一次请求、收一次回复"""
    with socket.create_connection((SERVER_IP, SERVER_PORT), timeout=5) as sock:
        sock.sendall((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))

        buf = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("服务端断开连接")
            buf.extend(chunk)
            i = buf.find(b"\n")
            if i != -1:
                line = bytes(buf[:i]).decode("utf-8", errors="replace")
                return json.loads(line)

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

        self.window.setWindowTitle("客户端")
        self.window.setWindowIcon(QIcon(icon_path))

        self.interfaceWidget = self.window.findChild(QStackedWidget, "interfaceWidget")
        self.loginButton = self.window.findChild(QPushButton, "loginButton")
        self.enrollButton = self.window.findChild(QPushButton, "enrollButton")

        # ====== 你要把下面这些 objectName 改成你 UI 里的 ======
        self.userNameEdit = self.window.findChild(QLineEdit, "userNameEdit")   # 登录用户名
        self.userPwdEdit = self.window.findChild(QLineEdit, "userPwdEdit")   # 登录密码

        self.enrollUserNameEdit = self.window.findChild(QLineEdit, "enrollUserNameEdit")       # 注册用户名
        self.enrollUserPwdEdit = self.window.findChild(QLineEdit, "enrollUserPwdEdit")       # 注册密码
        self.enrollSummitButton = self.window.findChild(QPushButton, "enrollSummitButton")   # 注册提交按钮
        # ================================================

    def bind_signals(self):
        self.loginButton.clicked.connect(self.do_login)
        self.enrollButton.clicked.connect(lambda: self.interfaceWidget.setCurrentIndex(1))
        self.enrollSummitButton.clicked.connect(self.do_register)

    def popup(self, title, msg, ok=True):
        if ok:
            QMessageBox.information(self.window, title, msg)
        else:
            QMessageBox.warning(self.window, title, msg)

    def do_register(self):
        username = (self.enrollUserNameEdit.text() if self.enrollUserNameEdit else "").strip()
        password = (self.enrollUserPwdEdit.text() if self.enrollUserPwdEdit else "")
        if not username or not password:
            self.popup("注册失败", "用户名/密码不能为空", ok=False)
            return

        try:
            resp = send_req({"action": "register", "username": username, "password": password})
            self.popup("注册结果", resp.get("msg", ""), ok=resp.get("ok", False))
            if resp.get("ok"):
                self.interfaceWidget.setCurrentIndex(0)  # 注册成功跳到登录页
        except Exception as e:
            self.popup("网络错误", str(e), ok=False)

    def do_login(self):
        username = (self.userNameEdit.text() if self.userNameEdit else "").strip()
        password = (self.userPwdEdit.text() if self.userPwdEdit else "")
        if not username or not password:
            self.popup("登录失败", "用户名/密码不能为空", ok=False)
            return

        try:
            resp = send_req({"action": "login", "username": username, "password": password})
            self.popup("登录结果", resp.get("msg", ""), ok=resp.get("ok", False))
            if resp.get("ok"):
                self.interfaceWidget.setCurrentIndex(2)
                pass
        except Exception as e:
            self.popup("网络错误", str(e), ok=False)

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # 不真的发送数据，只是借路由表获取本机IP
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip


app = QApplication(sys.argv)
w = MainWindow()
w.window.show()
sys.exit(app.exec())
