import sys, os, json, socket, threading
from PySide6.QtWidgets import (
    QApplication, QStackedWidget, QPushButton, QLineEdit, QMessageBox,
    QListWidget, QListWidgetItem, QTextEdit, QLabel, QWidget, QHBoxLayout, QToolButton,
    QFileDialog
)
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import QFile, QIODevice, QObject, Signal, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QAbstractItemView
import ipaddress
import re
from PySide6.QtGui import QDesktopServices
from PySide6.QtCore import QUrl
from datetime import datetime

ui_path = r"D:\0_Computer_Network_Course_Design\second_client\client.ui"
icon_path = r"D:\0_Computer_Network_Course_Design\second_client\icon.ico"
eye_open = r"D:\0_Computer_Network_Course_Design\second_client\eye_open.ico"
eye_close = r"D:\0_Computer_Network_Course_Design\second_client\eye_close.ico"

def send_request(server_ip, server_port, req):
    with socket.create_connection((server_ip, server_port), timeout=5) as sock:
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

def getLocalIp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

def recv_line(conn: socket.socket, buf: bytearray):
    while True:
        i = buf.find(b"\n")
        if i != -1:
            line = bytes(buf[:i])
            del buf[:i + 1]
            return line.decode("utf-8", errors="replace")
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf.extend(chunk)

def recv_exact(conn: socket.socket, size: int):
    data = b""
    while len(data) < size:
        chunk = conn.recv(min(4096, size - len(data)))
        if not chunk:
            raise ConnectionError("文件接收中断")
        data += chunk
    return data


def send_json(conn: socket.socket, obj: dict):
    conn.sendall((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))

class UiEmitter(QObject):
    users_update = Signal(list)            # list[dict]
    msg_in = Signal(str, str, object)         # from, to, text
    info = Signal(str)

class MainWindow:
    def __init__(self):
        self.sock = None
        self.recv_thread = None
        self.stop_recv = threading.Event()

        self.username = ""
        self.local_ip = getLocalIp()

        # peer -> {"messages":[(is_me,text)], "unread":int, "online":bool, "ip":str}
        self.sessions = {}
        self.current_peer = None

        self.emitter = UiEmitter()
        self.load_ui()
        self.bind_signals()

        self.emitter.users_update.connect(self.on_users_update)
        self.emitter.msg_in.connect(self.on_message_in)
        self.emitter.info.connect(lambda s: self.popUp("提示", s, ok=True))

        self.last_msg_time = None

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

        self.userNameEdit = self.window.findChild(QLineEdit, "userNameEdit")
        self.userPwdEdit = self.window.findChild(QLineEdit, "userPwdEdit")

        self.enrollUserNameEdit = self.window.findChild(QLineEdit, "enrollUserNameEdit")
        self.enrollUserPwdEdit = self.window.findChild(QLineEdit, "enrollUserPwdEdit")
        self.enrollSummitButton = self.window.findChild(QPushButton, "enrollSummitButton")
        self.enrollServerIPEdit = self.window.findChild(QLineEdit, "enrollServerIPEdit")
        self.enrollServerPortEdit = self.window.findChild(QLineEdit, "enrollServerPortEdit")

        self.serverIPEdit = self.window.findChild(QLineEdit, "serverIPEdit")
        self.serverPortEdit = self.window.findChild(QLineEdit, "serverPortEdit")

        self.loginEyeButton = self.window.findChild(QToolButton, "loginEyeButton")
        if self.userPwdEdit:
            self.userPwdEdit.setEchoMode(QLineEdit.Password)
        if self.loginEyeButton:
            self.loginEyeButton.setCheckable(True)
            self.loginEyeButton.setIcon(QIcon(eye_close))

        # 聊天页控件（index=2）
        self.chatListWidget = self.window.findChild(QListWidget, "chatListWidget")
        self.messageListWidget = self.window.findChild(QListWidget, "messageListWidget")
        self.inputTextEdit = self.window.findChild(QTextEdit, "inputTextEdit")
        self.sendMsgButton = self.window.findChild(QPushButton, "sendMsgButton")
        self.sendFileButton = self.window.findChild(QPushButton, "sendFileButton")

        self.messageListWidget.setSpacing(3)

        # 左侧用户列表：选中高亮（QSS）
        if self.chatListWidget:
            self.chatListWidget.setSelectionMode(QAbstractItemView.SingleSelection)
            self.chatListWidget.setStyleSheet("""
                QListWidget {
                    background: #FFFFFF;
                    border: 1px solid #E5E5E5;
                    outline: 0;
                }
                QListWidget::item {
                    padding: 10px 8px;
                    margin: 2px 6px;
                    border-radius: 8px;
                }
                QListWidget::item:hover {
                    background: #F2F6FF;
                }
                QListWidget::item:selected {
                    background: #DCEBFF;
                    color: #003A8C;
                    font-weight: 600;
                }
            """)

        self.messageListWidget.itemDoubleClicked.connect(self.open_file)

    def bind_signals(self):
        self.loginButton.clicked.connect(self.do_login)
        self.enrollButton.clicked.connect(lambda: self.interfaceWidget.setCurrentIndex(1))
        self.enrollSummitButton.clicked.connect(self.do_register)

        if self.sendMsgButton:
            self.sendMsgButton.clicked.connect(self.send_chat_message)
        if self.chatListWidget:
            self.chatListWidget.itemClicked.connect(self.on_peer_clicked)
        if self.sendFileButton:
            self.sendFileButton.clicked.connect(self.send_file)

        if self.loginEyeButton and self.userPwdEdit:
            self.loginEyeButton.toggled.connect(
                lambda checked: self.toggle_password(self.userPwdEdit, self.loginEyeButton, checked))

    def popUp(self, title, msg, ok=True):
        if ok:
            QMessageBox.information(self.window, title, msg)
        else:
            QMessageBox.warning(self.window, title, msg)

    def isValidIp(self, IP):
        s = (IP or "").strip()
        try:
            return ipaddress.ip_address(s).version == 4
        except ValueError:
            return False

    def is_valid_username(self, username: str):
        username = (username or "").strip()
        if not username:
            return False, "用户名不能为空"
        # 不能以数字开头
        if username[0].isdigit():
            return False, "用户名不能以数字开头"
        return True, ""

    def is_strong_password(self, password: str):
        password = password or ""
        if len(password) < 6:
            return False, "密码长度不能少于6位"
        if not re.search(r"[A-Za-z]", password):
            return False, "密码必须包含字母"
        if not re.search(r"\d", password):
            return False, "密码必须包含数字"
        # 特殊字符：只要不是字母数字即可
        if not re.search(r"[^A-Za-z0-9]", password):
            return False, "密码必须包含特殊字符"
        return True, ""

    def do_register(self):
        userName = (self.enrollUserNameEdit.text() if self.enrollUserNameEdit else "")
        password = (self.enrollUserPwdEdit.text() if self.enrollUserPwdEdit else "")
        serverIP = (self.enrollServerIPEdit.text() if self.enrollServerIPEdit else "")
        serverPort = int((self.enrollServerPortEdit.text() if self.enrollServerPortEdit else "0") or "0")

        if not self.isValidIp(serverIP):
            self.popUp("注册失败","服务器IP格式不合法", ok=False)

        ok_u, msg_u = self.is_valid_username(userName)
        if not ok_u:
            self.popUp("注册失败", msg_u, ok=False)
            return

        ok_p, msg_p = self.is_strong_password(password)
        if not ok_p:
            self.popUp("注册失败", msg_p, ok=False)
            return

        try:
            resp = send_request(serverIP, serverPort, {
                "action": "register",
                "username": userName,
                "password": password
            })
            self.popUp("注册结果", resp.get("msg", ""), ok=resp.get("ok", False))
            if resp.get("ok"):
                self.interfaceWidget.setCurrentIndex(0)
        except Exception as e:
            self.popUp("网络错误，请检查服务器IP", str(e), ok=False)

    def do_login(self):
        username = (self.userNameEdit.text() if self.userNameEdit else "").strip()
        password = (self.userPwdEdit.text() if self.userPwdEdit else "")
        serverIP = (self.serverIPEdit.text() if self.serverIPEdit else "").strip()
        serverPort = int((self.serverPortEdit.text() if self.serverPortEdit else "0") or "0")

        if not self.isValidIp(serverIP):
            self.popUp("登录失败","服务器IP格式不合法", ok=False)
            return

        if not username or not password:
            self.popUp("登录失败", "用户名/密码不能为空", ok=False)
            return

        try:
            resp = send_request(serverIP, serverPort, {
                "action": "login",
                "username": username,
                "password": password,
                "client_ip": self.local_ip
            })
            self.popUp("登录结果", resp.get("msg", ""), ok=resp.get("ok", False))

            if resp.get("ok"):
                self.username = username
                self.interfaceWidget.setCurrentIndex(2)
                self.start_chat_connection(serverIP, serverPort)

        except Exception as e:
            self.popUp("网络错误，请检查服务器IP", str(e), ok=False)

    def toggle_password(self, edit: QLineEdit, btn: QToolButton, checked: bool):
        """
        checked=True  -> 显示明文
        checked=False -> 隐藏密码
        """
        if checked:
            edit.setEchoMode(QLineEdit.Normal)
            btn.setIcon(QIcon(eye_open))
        else:
            edit.setEchoMode(QLineEdit.Password)
            btn.setIcon(QIcon(eye_close))

        # 保持光标在末尾（体验更像微信/QQ）
        edit.setFocus()
        edit.setCursorPosition(len(edit.text()))

    # ====== 长连接 ======
    def start_chat_connection(self, server_ip, server_port):
        self.close_chat_connection()
        try:
            self.sock = socket.create_connection((server_ip, server_port), timeout=5)
            self.sock.settimeout(None)
            self.stop_recv.clear()

            # 上线
            send_json(self.sock, {
                "action": "online",
                "username": self.username,
                "client_ip": self.local_ip
            })

            self.recv_thread = threading.Thread(target=self.recv_loop, daemon=True)
            self.recv_thread.start()

            self.emitter.info.emit(f"已连接 {server_ip}:{server_port}  本机IP={self.local_ip}")
        except Exception as e:
            self.popUp("连接失败", str(e), ok=False)

    def close_chat_connection(self):
        try:
            self.stop_recv.set()
            if self.sock:
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self.sock.close()
        finally:
            self.sock = None

    def recv_loop(self):
        buf = bytearray()
        try:
            while not self.stop_recv.is_set():
                line = recv_line(self.sock, buf)
                if line is None:
                    break

                try:
                    msg = json.loads(line)
                except Exception:
                    continue

                action = msg.get("action")

                if action == "user_state_list":
                    users = msg.get("users", [])
                    self.emitter.users_update.emit(users)

                elif action == "msg":
                    _from = msg.get("from", "")
                    _to = msg.get("to", "")
                    text = msg.get("text", "")
                    self.emitter.msg_in.emit(_from, _to, text)


                elif action == "file_meta":
                    _from = msg.get("from", "")
                    filename = msg.get("filename", "")
                    filesize = int(msg.get("filesize", 0))
                    save_path = os.path.join(
                        os.path.expanduser("~/Downloads"), filename
                    )
                    try:
                        remaining = filesize
                        file_data = b""

                        # ⭐ 先消耗 buf 里的残留（非常重要）
                        if len(buf) > 0:
                            take = min(len(buf), remaining)
                            file_data += bytes(buf[:take])
                            del buf[:take]
                            remaining -= take

                        # ⭐ 再从 socket 收剩余
                        while remaining > 0:
                            chunk = self.sock.recv(min(4096, remaining))
                            if not chunk:
                                raise ConnectionError("文件接收中断")
                            file_data += chunk
                            remaining -= len(chunk)

                        with open(save_path, "wb") as f:
                            f.write(file_data)

                        self.emitter.msg_in.emit(
                            _from,
                            self.username,
                            {
                                "type": "file",
                                "filename": filename,
                                "path": save_path,
                                "is_me": False
                            }
                        )
                    except Exception as e:
                        self.emitter.info.emit(f"接收文件失败：{e}")

                else:
                    # 可能是 {"ok":true,"msg":"已上线"} 这种确认包，忽略即可
                    pass

        except Exception as e:
            self.emitter.info.emit(f"接收线程异常：{e}")
        finally:
            self.close_chat_connection()

    # ====== 用户列表刷新 ======
    def on_users_update(self, users: list):
        # users: [{"username":"alice","online":True,"ip":"x.x.x.x"}, ...]
        # 让所有用户都存在于 sessions（离线也保留会话）
        for u in users:
            name = (u.get("username") or "").strip()
            if not name:
                continue
            self.sessions.setdefault(name, {"messages": [], "unread": 0, "online": False, "ip": ""})
            self.sessions[name]["online"] = bool(u.get("online", False))
            self.sessions[name]["ip"] = u.get("ip", "") or ""

        if self.chatListWidget is None:
            return

        self.chatListWidget.clear()

        peers = [k for k in self.sessions.keys() if k != self.username]
        peers.sort()

        for peer in peers:
            s = self.sessions[peer]
            unread = s["unread"]
            online = "在线" if s["online"] else "离线"
            last = ""
            if s["messages"]:
                last_msg = s["messages"][-1]

                # ===== 文件消息 =====
                if isinstance(last_msg, dict):
                    last = f"[文件] {last_msg.get('filename', '')}"
                else:
                    last = last_msg[1]

                if len(last) > 12:
                    last = last[:12] + "..."

            text = f"{peer}  [{online}]"
            if unread > 0:
                text += f"  ({unread})"
            if last:
                text += f"\n{last}"

            # if online == "在线":
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, peer)
            self.chatListWidget.addItem(item)

        if self.current_peer is None and self.chatListWidget.count() > 0:
            self.chatListWidget.setCurrentRow(0)
            self.on_peer_clicked(self.chatListWidget.item(0))

        if self.current_peer:
            for i in range(self.chatListWidget.count()):
                it = self.chatListWidget.item(i)
                if it.data(Qt.UserRole) == self.current_peer:
                    self.chatListWidget.setCurrentRow(i)  # 重新高亮
                    break

    def on_peer_clicked(self, item: QListWidgetItem):
        peer = item.data(Qt.UserRole)
        self.current_peer = peer

        if peer in self.sessions:
            self.sessions[peer]["unread"] = 0

        self.refresh_message_view(peer)
        # 刷新左侧（更新未读显示）
        self.on_users_update([
            {"username": k, "online": v["online"], "ip": v["ip"]}
            for k, v in self.sessions.items()
        ])

    # ====== 消息气泡显示 ======
    def refresh_message_view(self, peer: str):
        if self.messageListWidget is None:
            return
        self.messageListWidget.clear()
        msgs = self.sessions.get(peer, {}).get("messages", [])
        for m in msgs:
            if isinstance(m, dict):
                self.add_message_bubble(m)
            else:
                is_me, text = m
                self.add_message_bubble(text, is_me)

    def add_message_bubble(self, msg, is_me=None):
        item = QListWidgetItem()
        item.setFlags(item.flags() ^ Qt.ItemIsSelectable)

        w = QWidget()
        layout = QHBoxLayout(w)
        layout.setContentsMargins(10, 2, 10, 2)

        # ===== 文件消息 =====
        if isinstance(msg, dict) and msg.get("type") == "file":
            filename = msg["filename"]
            path = msg["path"]
            is_me = msg["is_me"]

            bubble = QLabel(f"📄 {filename}\n双击打开")
            bubble.setWordWrap(True)
            bubble.setStyleSheet("""
                QLabel{
                    padding:10px;
                    border-radius:10px;
                    background:#E8F0FE;
                    border:1px solid #C3D3F5;
                }
            """)

            # ⭐ 关键：把文件路径绑在 item 上
            print("path:", path)
            item.setData(Qt.UserRole, path)


        # ===== 普通文本消息 =====
        else:
            text = msg if isinstance(msg, str) else msg[1]
            bubble = QLabel(text)
            bubble.setWordWrap(True)
            bubble.setMaximumWidth(360)
            bubble.setStyleSheet("""
                QLabel{
                    padding:8px 10px;
                    border-radius:10px;
                    background:#DCF8C6;
                }
            """ if is_me else """
                QLabel{
                    padding:8px 10px;
                    border-radius:10px;
                    background:#FFFFFF;
                    border:1px solid #E5E5E5;
                }
            """)

        if is_me:
            layout.addStretch()
            layout.addWidget(bubble)
        else:
            layout.addWidget(bubble)
            layout.addStretch()

        now = datetime.now()

        # 判断是否需要显示时间
        if self.last_msg_time is None or (now - self.last_msg_time).total_seconds() >= 120:
            time_str = now.strftime("%H:%M")
            self.add_time_item(time_str)

        self.last_msg_time = now

        self.messageListWidget.addItem(item)
        self.messageListWidget.setItemWidget(item, w)
        item.setSizeHint(w.sizeHint())
        self.messageListWidget.scrollToBottom()

    # ====== 收到消息 ======
    def on_message_in(self, _from: str, _to: str, data):
        if isinstance(data, dict) and data.get("type") == "file":
            text = f"[文件] {data.get('filename')}"
            msg = {
                "type": "file",
                "is_me": False,
                "filename": data.get('filename'),
                "path": data.get('path'),
            }
        else:
            text = data

        peer = _from if _from != self.username else _to
        self.sessions.setdefault(peer, {"messages": [], "unread": 0, "online": True, "ip": ""})

        is_me = (_from == self.username)
        self.sessions[peer]["messages"].append((is_me, text))

        if self.current_peer == peer:
            if isinstance(data, dict) and data.get("type") == "file":
                self.add_message_bubble(msg, is_me)
            else:
                self.add_message_bubble(text, is_me)
        else:
            self.sessions[peer]["unread"] += 1

        self.on_users_update([
            {"username": k, "online": v["online"], "ip": v["ip"]}
            for k, v in self.sessions.items()
        ])

    # ====== 发送消息 ======
    def send_chat_message(self):
        if self.sock is None:
            self.popUp("发送失败", "未连接服务器", ok=False)
            return
        if self.current_peer is None:
            self.popUp("发送失败", "请先在左侧选择一个用户/会话", ok=False)
            return
        if self.inputTextEdit is None:
            return

        text = self.inputTextEdit.toPlainText().strip()
        if not text:
            return

        try:
            send_json(self.sock, {
                "action": "msg",
                "from": self.username,
                "to": self.current_peer,
                "text": text,
                "client_ip": self.local_ip
            })

            # 本地先显示（立即出现）
            self.on_message_in(self.username, self.current_peer, text)
            self.inputTextEdit.clear()

        except Exception as e:
            self.popUp("发送失败", str(e), ok=False)

    def send_file(self):
        if not self.sock or not self.current_peer:
            self.popUp("发送失败", "未选择聊天对象", ok=False)
            return

        path, _ = QFileDialog.getOpenFileName(
            self.window, "选择要发送的文件", "", "All Files (*)"
        )
        if not path:
            return

        filename = os.path.basename(path)
        filesize = os.path.getsize(path)

        try:
            # 1️⃣ 先发 meta
            send_json(self.sock, {
                "action": "file_meta",
                "from": self.username,
                "to": self.current_peer,
                "filename": filename,
                "filesize": filesize
            })

            # 2️⃣ 再发文件内容
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    self.sock.sendall(chunk)

            # 本地显示
            msg = {
                "type": "file",
                "is_me": True,
                "filename": filename,
                "path": path
            }
            self.sessions[self.current_peer]["messages"].append(msg)
            self.add_message_bubble(msg)

        except Exception as e:
            self.popUp("发送失败", str(e), ok=False)

    def open_file(self, item: QListWidgetItem):
        path = item.data(Qt.UserRole)
        if path == None:
            return
        if path and os.path.exists(path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        else:
            QMessageBox.warning(self.window, "无法打开", "文件不存在或已被删除")

    def add_time_item(self, time_text):
        item = QListWidgetItem()

        label = QLabel(time_text)
        label.setAlignment(Qt.AlignCenter)
        label.setStyleSheet("""
            QLabel {
                color: #888;
                background: transparent;
                padding: 4px;
            }
        """)

        item.setSizeHint(label.sizeHint())
        self.messageListWidget.addItem(item)
        self.messageListWidget.setItemWidget(item, label)


app = QApplication(sys.argv)
w = MainWindow()
w.window.show()
sys.exit(app.exec())
