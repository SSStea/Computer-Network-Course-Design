import sys, os, json, socket, threading, sqlite3, hashlib
from PySide6.QtWidgets import QApplication, QPushButton, QLineEdit, QTableWidget, QTableWidgetItem, QListWidget
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import QFile, QIODevice, QObject, Signal
from PySide6.QtGui import QIcon
import time


ui_path = r"D:\0_Computer_Network_Course_Design\second_server\server.ui"
icon_path = r"D:\0_Computer_Network_Course_Design\second_server\icon.ico"

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

DB_PATH = os.path.join(os.path.dirname(__file__), "user.db")

def hash_pw(pw):
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def register_user(username, password):
    username = (username or "").strip()
    password = password or ""
    if not username or not password:
        return False, "用户名或密码不能为空"

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users(username, password_hash) VALUES(?,?)",
                    (username, hash_pw(password)))
        conn.commit()
        return True, "注册成功"
    except sqlite3.IntegrityError:
        return False, "用户名已存在"
    finally:
        conn.close()

def verify_user(username, password):
    username = (username or "").strip()
    password = password or ""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return False, "用户不存在"
    if row[0] != hash_pw(password):
        return False, "密码错误"
    return True, "登录成功"

def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username FROM users ORDER BY id ASC")
    rows = cur.fetchall()
    conn.close()
    return [r[0] for r in rows]

def send_json(conn, obj):
    conn.sendall((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))

def recv_line(conn: socket.socket, buf: bytearray):
    while True:
        i = buf.find(b"\n")
        if i != -1:
            line = bytes(buf[:i])
            del buf[:i+1]
            return line.decode("utf-8", errors="replace")

        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf.extend(chunk)

# ====== UI信号 ======
class UIEmitter(QObject):
    init_users = Signal(list)          # [(username, status, ip), ...]
    update_user = Signal(str, str, str)  # username, status, ip
    add_log = Signal(str)

class MainWindow:
    def __init__(self):
        # username -> {"status": "离线/在线", "ip": ""}
        self.user_states = {}
        # 在线连接：username -> conn
        self.online_conns = {}
        self.lock = threading.Lock()

        self.emitter = UIEmitter()
        self.load_ui()
        self.bind_signals()

        self.emitter.init_users.connect(self.ui_init_user_table)
        self.emitter.update_user.connect(self.ui_update_user_row)
        self.emitter.add_log.connect(self.ui_add_log)

    def load_ui(self):
        loader = QUiLoader()
        file = QFile(ui_path)
        file.open(QIODevice.ReadOnly)
        self.window = loader.load(file)
        file.close()

        self.window.setWindowTitle("服务端")
        self.window.setWindowIcon(QIcon(icon_path))

        self.serverIPEdit = self.window.findChild(QLineEdit, "serverIPEdit")
        self.serverPortEdit = self.window.findChild(QLineEdit, "serverPortEdit")
        self.startButton = self.window.findChild(QPushButton, "startButton")

        self.serverIPEdit.setText(get_local_ip())
        self.serverPortEdit.setText("5000")

        self.userListWidget = self.window.findChild(QTableWidget, "userListWidget")
        self.userListWidget.setColumnCount(3)
        self.userListWidget.setHorizontalHeaderLabels(["用户名", "状态", "IP"])

        self.messageHistoryWidget = self.window.findChild(QListWidget, "messageHistoryWidget")

    def bind_signals(self):
        self.startButton.clicked.connect(self.start_server_thread)

    # ====== UI更新 ======
    def ui_init_user_table(self, rows):
        table = self.userListWidget
        table.setRowCount(0)
        for username, status, ip in rows:
            r = table.rowCount()
            table.insertRow(r)
            table.setItem(r, 0, QTableWidgetItem(username))
            table.setItem(r, 1, QTableWidgetItem(status))
            table.setItem(r, 2, QTableWidgetItem(ip))

    def ui_update_user_row(self, username, status, ip):
        table = self.userListWidget
        target_row = -1
        for r in range(table.rowCount()):
            item = table.item(r, 0)
            if item and item.text() == username:
                target_row = r
                break
        if target_row == -1:
            target_row = table.rowCount()
            table.insertRow(target_row)
            table.setItem(target_row, 0, QTableWidgetItem(username))
        table.setItem(target_row, 1, QTableWidgetItem(status))
        table.setItem(target_row, 2, QTableWidgetItem(ip))

    def ui_add_log(self, text: str):
        # 主线程更新 messageHistoryWidget
        if not self.messageHistoryWidget:
            return
        self.messageHistoryWidget.addItem(text)
        self.messageHistoryWidget.scrollToBottom()

    def log_event(self, who: str, what: str):
        # t = threading.current_thread().name  # 可选：调试线程用
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"{now}：{who}{what}"
        self.emitter.add_log.emit(line)

    # ====== 状态列表（发给客户端） ======
    def build_user_state_payload(self):
        with self.lock:
            payload = []
            for u, v in self.user_states.items():
                payload.append({
                    "username": u,
                    "online": (v.get("status") == "在线"),
                    "ip": v.get("ip", "")
                })
            return payload

    def broadcast_user_state_list(self):
        msg = {"action": "user_state_list", "users": self.build_user_state_payload()}
        with self.lock:
            conns = list(self.online_conns.items())  # [(username, conn)]
        # 不持锁发送，避免卡住
        for uname, c in conns:
            try:
                send_json(c, msg)
            except Exception:
                # 发送失败，清理
                self.mark_offline(uname)

    def mark_offline(self, username):
        with self.lock:
            if username in self.user_states:
                self.user_states[username]["status"] = "离线"
                self.user_states[username]["ip"] = ""
            if username in self.online_conns:
                try:
                    self.online_conns[username].close()
                except Exception:
                    pass
                self.online_conns.pop(username, None)
        self.emitter.update_user.emit(username, "离线", "")
        self.broadcast_user_state_list()

    # ====== 点击启动 ======
    def start_server_thread(self):
        init_db()

        usernames = get_all_users()
        with self.lock:
            self.user_states = {u: {"status": "离线", "ip": ""} for u in usernames}
            self.online_conns = {}

        init_rows = [(u, "离线", "") for u in usernames]
        self.emitter.init_users.emit(init_rows)

        self.log_event("系统",
                       f"服务端启动，监听 {self.serverIPEdit.text().strip()}:{self.serverPortEdit.text().strip()}，已加载用户 {len(usernames)} 个")

        t = threading.Thread(target=self.server_loop, daemon=True)
        t.start()

    def server_loop(self):
        serverIP = self.serverIPEdit.text().strip()
        serverPort = int(self.serverPortEdit.text().strip())

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((serverIP, serverPort))
        s.listen(50)
        print(f"[SERVER] listening on {serverIP}:{serverPort}")

        while True:
            conn, addr = s.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

    def handle_client(self, conn, addr):
        print("[SERVER] client:", addr)
        buf = bytearray()
        bound_username = None  # 这个连接对应的在线用户名（如果进入online）

        try:
            while True:
                line = recv_line(conn, buf)
                if line is None:
                    break

                try:
                    req = json.loads(line)
                except json.JSONDecodeError:
                    send_json(conn, {"ok": False, "msg": "请求不是合法JSON"})
                    continue

                action = req.get("action")
                username = (req.get("username") or "").strip()
                password = req.get("password") or ""
                client_ip = (req.get("client_ip") or "").strip() or addr[0]

                if action == "register":
                    ok, msg = register_user(username, password)
                    self.log_event(username or "未知用户", f"尝试注册（结果：{msg}）")
                    if ok:
                        # 新用户也加入状态表：离线
                        with self.lock:
                            self.user_states.setdefault(username, {"status": "离线", "ip": ""})
                        self.emitter.update_user.emit(username, "离线", "")
                        self.broadcast_user_state_list()
                    send_json(conn, {"ok": ok, "msg": msg})

                elif action == "login":
                    ok, msg = verify_user(username, password)
                    self.log_event(username or "未知用户", f"尝试登录校验（结果：{msg}）")
                    if ok:
                        # 这里只做“校验成功回包”，真正上线由 online 来确定长连接
                        send_json(conn, {"ok": True, "msg": msg})
                    else:
                        send_json(conn, {"ok": False, "msg": msg})

                elif action == "online":
                    if not username:
                        send_json(conn, {"ok": False, "msg": "username不能为空"})
                        continue

                    bound_username = username
                    with self.lock:
                        self.user_states.setdefault(username, {"status": "离线", "ip": ""})
                        self.user_states[username]["status"] = "在线"
                        self.user_states[username]["ip"] = client_ip
                        self.online_conns[username] = conn

                    # 更新服务端表格
                    self.emitter.update_user.emit(username, "在线", client_ip)
                    self.log_event(username, f"上线，IP={client_ip}")

                    # 先回复这条在线确认
                    send_json(conn, {"ok": True, "msg": "已上线"})

                    # 给刚上线的用户推一次全量列表 + 广播给所有在线用户
                    self.broadcast_user_state_list()

                elif action == "msg":
                    # 转发聊天消息：from -> to
                    _from = (req.get("from") or "").strip()
                    _to = (req.get("to") or "").strip()
                    text = req.get("text") or ""

                    if not _from or not _to:
                        send_json(conn, {"ok": False, "msg": "from/to不能为空"})
                        self.log_event(_from or "未知用户", "发送消息失败（from/to为空）")
                        continue

                    with self.lock:
                        target_conn = self.online_conns.get(_to)

                    if target_conn:
                        try:
                            send_json(target_conn, {"action": "msg", "from": _from, "to": _to, "text": text})
                            send_json(conn, {"ok": True, "msg": "已发送"})
                            self.log_event(_from, f"给{_to}发送消息:{text}")
                        except Exception:
                            send_json(conn, {"ok": False, "msg": "对方连接异常"})
                            self.log_event(_from, f"给{_to}发送失败（对方连接异常）")
                            self.mark_offline(_to)
                    else:
                        send_json(conn, {"ok": False, "msg": "对方不在线"})
                        self.log_event(_from, f"给{_to}发送失败（对方不在线）")

                else:
                    send_json(conn, {"ok": False, "msg": "未知action"})

        except Exception as e:
            print("[SERVER] error:", e)
        finally:
            # 连接断开：如果这个连接绑定了在线用户，则置离线并广播
            try:
                conn.close()
            except Exception:
                pass

            if bound_username:
                self.log_event(bound_username, "下线（连接断开）")
                self.mark_offline(bound_username)


app = QApplication(sys.argv)
w = MainWindow()
w.window.show()
sys.exit(app.exec())
