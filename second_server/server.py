import sys, os, json, socket, threading, sqlite3, hashlib
from PySide6.QtWidgets import QApplication
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import QFile, QIODevice
from PySide6.QtGui import QIcon

ui_path = r"D:\0_Computer_Network_Course_Design\second_server\server.ui"
icon_path = r"D:\0_Computer_Network_Course_Design\second_server\icon.ico"

HOST = "0.0.0.0"
PORT = 5000
DB_PATH = os.path.join(os.path.dirname(__file__), "user.db")


# ---------------- DB(内嵌) ----------------
def hash_pw(pw: str) -> str:
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

def register_user(username: str, password: str):
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

def verify_user(username: str, password: str):
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


# ---------------- TCP协议：一行JSON + '\n' ----------------
def send_json(conn: socket.socket, obj: dict):
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


class MainWindow:
    def __init__(self):
        self.load_ui()
        self.start_server_thread()

    def load_ui(self):
        loader = QUiLoader()
        file = QFile(ui_path)
        file.open(QIODevice.ReadOnly)
        self.window = loader.load(file)
        file.close()

        self.window.setWindowTitle("服务端")
        self.window.setWindowIcon(QIcon(icon_path))

    def start_server_thread(self):
        init_db()
        t = threading.Thread(target=self.server_loop, daemon=True)
        t.start()

    def server_loop(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(50)
        print(f"[SERVER] listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

    def handle_client(self, conn: socket.socket, addr):
        print("[SERVER] client:", addr)
        buf = bytearray()
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
                username = req.get("username", "")
                password = req.get("password", "")

                if action == "register":
                    ok, msg = register_user(username, password)
                    send_json(conn, {"ok": ok, "msg": msg})
                elif action == "login":
                    ok, msg = verify_user(username, password)
                    send_json(conn, {"ok": ok, "msg": msg})
                else:
                    send_json(conn, {"ok": False, "msg": "未知action"})
        except Exception as e:
            print("[SERVER] error:", e)
        finally:
            conn.close()


app = QApplication(sys.argv)
w = MainWindow()
w.window.show()
sys.exit(app.exec())
