
from flask import Flask, request, jsonify, render_template_string
import sqlite3, os, json, datetime, secrets, hashlib, hmac
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IS_RENDER = os.environ.get("RENDER", "").strip().lower() == "true"

def _env_secret(name, local_default=""):
    value = os.environ.get(name, "").strip()
    if value:
        return value
    if IS_RENDER:
        raise RuntimeError(
            f"Thiếu biến môi trường {name}. Hãy cấu hình biến này trong Render > Environment trước khi deploy."
        )
    return local_default

DATA_DIR = os.path.abspath(
    os.environ.get("CLOUD_DATA_DIR", "").strip() or os.path.join(BASE_DIR, "cloud_data")
)
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "cloud.db")

CLOUD_API_TOKEN = _env_secret("CLOUD_API_TOKEN", "demo-secret-token")
INITIAL_ADMIN_USERNAME = os.environ.get("INITIAL_ADMIN_USERNAME", "admin").strip() or "admin"
INITIAL_ADMIN_PASSWORD = _env_secret("INITIAL_ADMIN_PASSWORD", "admin123")
CLOUD_SESSION_HOURS = max(1, int(os.environ.get("CLOUD_SESSION_HOURS", "12")))
CLOUD_PUBLIC_DASHBOARD = os.environ.get(
    "CLOUD_PUBLIC_DASHBOARD", "false" if IS_RENDER else "true"
).strip().lower() in ("1", "true", "yes", "on")

if IS_RENDER and len(INITIAL_ADMIN_PASSWORD) < 8:
    raise RuntimeError("INITIAL_ADMIN_PASSWORD trên Render phải có ít nhất 8 ký tự.")
if IS_RENDER and len(CLOUD_API_TOKEN) < 16:
    raise RuntimeError("CLOUD_API_TOKEN trên Render phải có ít nhất 16 ký tự.")

app = Flask(__name__)

def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def now_text():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS auth_users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','teacher','student')),
        active INTEGER NOT NULL DEFAULT 1,
        student_code TEXT UNIQUE,
        class_id TEXT,
        created_by INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS auth_tokens(
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES auth_users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_id ON auth_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires_at ON auth_tokens(expires_at);

    CREATE TABLE IF NOT EXISTS stations(
        station_id TEXT PRIMARY KEY,
        last_seen TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sync_events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        station_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        received_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users_cloud(
        station_id TEXT NOT NULL,
        local_id TEXT NOT NULL,
        username TEXT NOT NULL,
        full_name TEXT,
        role TEXT,
        is_active INTEGER,
        student_id TEXT,
        updated_at TEXT,
        PRIMARY KEY(station_id,local_id)
    );

    CREATE TABLE IF NOT EXISTS classes_cloud(
        station_id TEXT NOT NULL,
        local_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        updated_at TEXT,
        PRIMARY KEY(station_id,local_id)
    );

    CREATE TABLE IF NOT EXISTS students_cloud(
        station_id TEXT NOT NULL,
        local_id TEXT NOT NULL,
        student_code TEXT,
        full_name TEXT,
        class_id TEXT,
        updated_at TEXT,
        PRIMARY KEY(station_id,local_id)
    );

    CREATE TABLE IF NOT EXISTS scenarios_cloud(
        station_id TEXT NOT NULL,
        local_id TEXT NOT NULL,
        name TEXT,
        difficulty TEXT,
        channels TEXT,
        description TEXT,
        updated_at TEXT,
        PRIMARY KEY(station_id,local_id)
    );

    CREATE TABLE IF NOT EXISTS saved_reports_cloud(
        station_id TEXT NOT NULL,
        local_id TEXT NOT NULL,
        title TEXT NOT NULL,
        created_by TEXT,
        created_at TEXT,
        quiz_count INTEGER DEFAULT 0,
        fault_log_count INTEGER DEFAULT 0,
        content_json TEXT,
        PRIMARY KEY(station_id,local_id)
    );

    CREATE TABLE IF NOT EXISTS question_bank(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        question TEXT NOT NULL,
        a TEXT NOT NULL,
        b TEXT NOT NULL,
        c TEXT NOT NULL,
        d TEXT NOT NULL,
        correct TEXT NOT NULL CHECK(correct IN ('A','B','C','D')),
        category TEXT NOT NULL DEFAULT 'Chung',
        difficulty TEXT NOT NULL DEFAULT 'Cơ bản',
        explanation TEXT DEFAULT '',
        active INTEGER NOT NULL DEFAULT 1,
        created_by INTEGER,
        created_by_name TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS quiz_sets(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT DEFAULT '',
        question_ids TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created_by INTEGER,
        created_by_name TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS quiz_results_cloud(
        station_id TEXT NOT NULL,
        local_id TEXT NOT NULL,
        student_name TEXT,
        score INTEGER,
        total INTEGER,
        created_at TEXT,
        PRIMARY KEY(station_id,local_id)
    );

    CREATE TABLE IF NOT EXISTS fault_logs_cloud(
        station_id TEXT NOT NULL,
        local_id TEXT NOT NULL,
        device_code TEXT,
        channel INTEGER,
        state INTEGER,
        action TEXT,
        actor TEXT,
        created_at TEXT,
        PRIMARY KEY(station_id,local_id)
    );
    """)
    admin = conn.execute("SELECT id FROM auth_users WHERE username=?", (INITIAL_ADMIN_USERNAME,)).fetchone()
    if not admin:
        conn.execute(
            """INSERT INTO auth_users(username,password_hash,full_name,role,active,created_at,updated_at)
               VALUES(?,?,?,?,1,?,?)""",
            (INITIAL_ADMIN_USERNAME, generate_password_hash(INITIAL_ADMIN_PASSWORD),
             "Quản trị viên", "admin", now_text(), now_text())
        )

    qcount = conn.execute("SELECT COUNT(*) c FROM question_bank").fetchone()["c"]
    if qcount == 0:
        ts = now_text()
        samples = [
            ("Điện áp danh định của ắc quy ô tô con thông dụng là bao nhiêu?","6V","12V","24V","48V","B","Điện ô tô","Cơ bản","Ắc quy ô tô con thông dụng có điện áp danh định 12 V."),
            ("Cảm biến CKP dùng để xác định chủ yếu thông tin nào?","Áp suất nhiên liệu","Nhiệt độ nước","Vị trí/tốc độ trục khuỷu","Mức nhiên liệu","C","Động cơ","Cơ bản","CKP cung cấp thông tin vị trí và tốc độ trục khuỷu."),
            ("Khi kiểm tra mạch điện, thao tác nào nên thực hiện trước?","Thay ECU ngay","Kiểm tra nguồn và mass","Cắt dây thử","Thay toàn bộ cảm biến","B","Chẩn đoán","Cơ bản","Nguồn và mass là các điều kiện nền tảng cần xác nhận trước."),
        ]
        conn.executemany(
            """INSERT INTO question_bank(question,a,b,c,d,correct,category,difficulty,explanation,active,created_by_name,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,1,'system',?,?)""",
            [(*q, ts, ts) for q in samples]
        )

    conn.commit()
    conn.close()

def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def authorized():
    supplied = request.headers.get("X-API-Key", "")
    return bool(supplied) and hmac.compare_digest(supplied, CLOUD_API_TOKEN)

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    return response

@app.route("/api/health")
def api_health():
    try:
        conn = db()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        return jsonify({
            "ok": True,
            "service": "OTO Training Cloud",
            "server_time": now_text(),
            "database": "ok"
        })
    except Exception:
        return jsonify({"ok": False, "service": "OTO Training Cloud", "database": "error"}), 503

def auth_current_user():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    token = h[7:].strip()
    if not token:
        return None
    th = token_hash(token)
    now = now_text()
    conn = db()
    row = conn.execute(
        """SELECT u.* FROM auth_tokens t
           JOIN auth_users u ON u.id=t.user_id
           WHERE t.token_hash=? AND t.expires_at>?""",
        (th, now)
    ).fetchone()
    if not row:
        conn.execute("DELETE FROM auth_tokens WHERE token_hash=? OR expires_at<=?", (th, now))
        conn.commit()
        conn.close()
        return None
    if not row["active"]:
        conn.execute("DELETE FROM auth_tokens WHERE token_hash=?", (th,))
        conn.commit()
        conn.close()
        return None
    conn.close()
    return dict(row)

def auth_can_manage(actor_role, target_role):
    if actor_role == "admin":
        return target_role in ("teacher", "student")
    if actor_role == "teacher":
        return target_role == "student"
    return False

def auth_user_dict(u):
    return {
        "id": u["id"],
        "username": u["username"],
        "full_name": u["full_name"],
        "role": u["role"],
        "active": bool(u["active"]),
        "student_code": u["student_code"],
        "class_id": u["class_id"],
        "updated_at": u["updated_at"],
    }

@app.route("/api/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    conn = db()
    u = conn.execute("SELECT * FROM auth_users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not u or not check_password_hash(u["password_hash"], password):
        return jsonify({"ok": False, "message": "Sai tài khoản hoặc mật khẩu"}), 401
    if not u["active"]:
        return jsonify({"ok": False, "message": "Tài khoản đã bị khóa"}), 403
    token = secrets.token_hex(32)
    created_at = datetime.datetime.now()
    expires_at = created_at + datetime.timedelta(hours=CLOUD_SESSION_HOURS)
    conn = db()
    conn.execute("DELETE FROM auth_tokens WHERE expires_at<=?", (now_text(),))
    conn.execute(
        "INSERT INTO auth_tokens(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
        (token_hash(token), u["id"], created_at.strftime("%Y-%m-%d %H:%M:%S"),
         expires_at.strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()
    return jsonify({
        "ok": True,
        "token": token,
        "expires_in_seconds": CLOUD_SESSION_HOURS * 3600,
        "user": auth_user_dict(u)
    })

@app.route("/api/logout", methods=["POST"])
def auth_logout():
    h = request.headers.get("Authorization", "")
    if h.startswith("Bearer "):
        raw = h[7:].strip()
        if raw:
            conn = db()
            conn.execute("DELETE FROM auth_tokens WHERE token_hash=?", (token_hash(raw),))
            conn.commit()
            conn.close()
    return jsonify({"ok": True})

@app.route("/api/users", methods=["GET"])
def auth_users_list():
    actor = auth_current_user()
    if not actor:
        return jsonify({"ok": False, "message": "Chưa đăng nhập hoặc phiên đã hết hạn"}), 401
    if actor["role"] not in ("admin", "teacher"):
        return jsonify({"ok": False, "message": "Không có quyền"}), 403
    conn = db()
    if actor["role"] == "admin":
        rows = conn.execute("SELECT * FROM auth_users WHERE role IN ('teacher','student') ORDER BY CASE role WHEN 'teacher' THEN 0 ELSE 1 END,id DESC").fetchall()
    else:
        rows = conn.execute("SELECT * FROM auth_users WHERE role='student' ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify({"ok": True, "users": [auth_user_dict(x) for x in rows]})

@app.route("/api/users", methods=["POST"])
def auth_users_create():
    actor = auth_current_user()
    if not actor:
        return jsonify({"ok": False, "message": "Chưa đăng nhập hoặc phiên đã hết hạn"}), 401
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    full_name = str(data.get("full_name", "")).strip()
    role = str(data.get("role", "")).strip().lower()
    student_code = str(data.get("student_code") or "").strip() or None
    class_id = str(data.get("class_id") or "").strip() or None
    if not auth_can_manage(actor["role"], role):
        return jsonify({"ok": False, "message": "Bạn không có quyền tạo loại tài khoản này"}), 403
    if len(username) < 3 or len(password) < 6 or not full_name:
        return jsonify({"ok": False, "message": "Tên đăng nhập tối thiểu 3 ký tự, mật khẩu tối thiểu 6 ký tự"}), 400
    if role == "student" and not student_code:
        student_code = username.upper()
    conn = db()
    if conn.execute("SELECT id FROM auth_users WHERE username=?", (username,)).fetchone():
        conn.close(); return jsonify({"ok": False, "message": "Tên đăng nhập đã tồn tại"}), 409
    if student_code and conn.execute("SELECT id FROM auth_users WHERE student_code=?", (student_code,)).fetchone():
        conn.close(); return jsonify({"ok": False, "message": "Mã sinh viên đã tồn tại"}), 409
    ts = now_text()
    cur = conn.execute(
        """INSERT INTO auth_users(username,password_hash,full_name,role,active,student_code,class_id,created_by,created_at,updated_at)
           VALUES(?,?,?,?,1,?,?,?,?,?)""",
        (username, generate_password_hash(password), full_name, role, student_code if role=="student" else None,
         class_id if role=="student" else None, actor["id"], ts, ts)
    )
    conn.commit()
    u = conn.execute("SELECT * FROM auth_users WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.close()
    return jsonify({"ok": True, "message": "Tạo tài khoản thành công", "user": auth_user_dict(u)}), 201

@app.route("/api/users/<int:user_id>/active", methods=["PUT"])
def auth_user_active(user_id):
    actor = auth_current_user()
    if not actor:
        return jsonify({"ok": False, "message": "Chưa đăng nhập"}), 401
    data = request.get_json(silent=True) or {}
    conn = db()
    target = conn.execute("SELECT * FROM auth_users WHERE id=?", (user_id,)).fetchone()
    if not target:
        conn.close(); return jsonify({"ok": False, "message": "Không tìm thấy tài khoản"}), 404
    if not auth_can_manage(actor["role"], target["role"]):
        conn.close(); return jsonify({"ok": False, "message": "Không có quyền"}), 403
    conn.execute("UPDATE auth_users SET active=?,updated_at=? WHERE id=?", (1 if data.get("active") else 0, now_text(), user_id))
    conn.commit(); target = conn.execute("SELECT * FROM auth_users WHERE id=?", (user_id,)).fetchone(); conn.close()
    return jsonify({"ok": True, "user": auth_user_dict(target)})

@app.route("/api/users/<int:user_id>", methods=["PATCH"])
def auth_user_update(user_id):
    actor = auth_current_user()
    if not actor:
        return jsonify({"ok": False, "message": "Chưa đăng nhập"}), 401
    data = request.get_json(silent=True) or {}
    conn = db()
    target = conn.execute("SELECT * FROM auth_users WHERE id=?", (user_id,)).fetchone()
    if not target:
        conn.close(); return jsonify({"ok": False, "message": "Không tìm thấy tài khoản"}), 404
    if not auth_can_manage(actor["role"], target["role"]):
        conn.close(); return jsonify({"ok": False, "message": "Không có quyền"}), 403
    full_name = str(data.get("full_name", target["full_name"])).strip() or target["full_name"]
    student_code = target["student_code"]
    class_id = target["class_id"]
    if target["role"] == "student":
        student_code = str(data.get("student_code", student_code) or "").strip() or target["username"].upper()
        class_id = str(data.get("class_id") or "").strip() or None
        dup = conn.execute("SELECT id FROM auth_users WHERE student_code=? AND id<>?", (student_code, user_id)).fetchone()
        if dup:
            conn.close(); return jsonify({"ok": False, "message": "Mã sinh viên đã tồn tại"}), 409
    conn.execute("UPDATE auth_users SET full_name=?,student_code=?,class_id=?,updated_at=? WHERE id=?",
                 (full_name, student_code, class_id, now_text(), user_id))
    new_password = str(data.get("new_password") or "")
    if new_password:
        if len(new_password) < 6:
            conn.close(); return jsonify({"ok": False, "message": "Mật khẩu mới tối thiểu 6 ký tự"}), 400
        conn.execute("UPDATE auth_users SET password_hash=?,updated_at=? WHERE id=?",
                     (generate_password_hash(new_password), now_text(), user_id))
    conn.commit(); target = conn.execute("SELECT * FROM auth_users WHERE id=?", (user_id,)).fetchone(); conn.close()
    return jsonify({"ok": True, "user": auth_user_dict(target)})


# =========================================================
# CENTRAL QUESTION BANK
# =========================================================
def question_dict(q, include_answer=True):
    data = {
        "id": q["id"],
        "question": q["question"],
        "a": q["a"], "b": q["b"], "c": q["c"], "d": q["d"],
        "category": q["category"],
        "difficulty": q["difficulty"],
        "active": bool(q["active"]),
        "created_by": q["created_by"],
        "created_by_name": q["created_by_name"],
        "created_at": q["created_at"],
        "updated_at": q["updated_at"],
    }
    if include_answer:
        data["correct"] = q["correct"]
        data["explanation"] = q["explanation"]
    return data


def require_question_manager():
    actor = auth_current_user()
    if not actor:
        return None, (jsonify({"ok": False, "message": "Chưa đăng nhập hoặc phiên đã hết hạn"}), 401)
    if actor["role"] not in ("admin", "teacher"):
        return None, (jsonify({"ok": False, "message": "Không có quyền quản lý câu hỏi"}), 403)
    return actor, None


@app.route("/api/questions", methods=["GET"])
def questions_list():
    actor = auth_current_user()
    if not actor:
        return jsonify({"ok": False, "message": "Chưa đăng nhập hoặc phiên đã hết hạn"}), 401
    conn = db()
    if actor["role"] in ("admin", "teacher"):
        rows = conn.execute("SELECT * FROM question_bank ORDER BY category,difficulty,id DESC").fetchall()
        result = [question_dict(x, True) for x in rows]
    else:
        rows = conn.execute("SELECT * FROM question_bank WHERE active=1 ORDER BY category,difficulty,id").fetchall()
        result = [question_dict(x, False) for x in rows]
    conn.close()
    return jsonify({"ok": True, "questions": result})


@app.route("/api/questions/<int:question_id>", methods=["GET"])
def question_get(question_id):
    actor, err = require_question_manager()
    if err: return err
    conn = db(); q = conn.execute("SELECT * FROM question_bank WHERE id=?", (question_id,)).fetchone(); conn.close()
    if not q:
        return jsonify({"ok": False, "message": "Không tìm thấy câu hỏi"}), 404
    return jsonify({"ok": True, "question": question_dict(q, True)})


def question_payload(data):
    return {
        "question": str(data.get("question", "")).strip(),
        "a": str(data.get("a", "")).strip(),
        "b": str(data.get("b", "")).strip(),
        "c": str(data.get("c", "")).strip(),
        "d": str(data.get("d", "")).strip(),
        "correct": str(data.get("correct", "A")).strip().upper(),
        "category": str(data.get("category", "Chung")).strip() or "Chung",
        "difficulty": str(data.get("difficulty", "Cơ bản")).strip() or "Cơ bản",
        "explanation": str(data.get("explanation", "")).strip(),
        "active": 1 if data.get("active", True) else 0,
    }


@app.route("/api/questions", methods=["POST"])
def question_create_api():
    actor, err = require_question_manager()
    if err: return err
    p = question_payload(request.get_json(silent=True) or {})
    if not all(p[k] for k in ("question","a","b","c","d")) or p["correct"] not in ("A","B","C","D"):
        return jsonify({"ok": False, "message": "Dữ liệu câu hỏi không hợp lệ"}), 400
    ts = now_text(); conn = db()
    cur = conn.execute(\
        """INSERT INTO question_bank(question,a,b,c,d,correct,category,difficulty,explanation,active,created_by,created_by_name,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (p["question"],p["a"],p["b"],p["c"],p["d"],p["correct"],p["category"],p["difficulty"],p["explanation"],p["active"],actor["id"],actor["full_name"],ts,ts)
    )
    conn.commit(); q = conn.execute("SELECT * FROM question_bank WHERE id=?", (cur.lastrowid,)).fetchone(); conn.close()
    return jsonify({"ok": True, "message": "Đã thêm câu hỏi", "question": question_dict(q, True)}), 201


@app.route("/api/questions/<int:question_id>", methods=["PUT"])
def question_update_api(question_id):
    actor, err = require_question_manager()
    if err: return err
    p = question_payload(request.get_json(silent=True) or {})
    if not all(p[k] for k in ("question","a","b","c","d")) or p["correct"] not in ("A","B","C","D"):
        return jsonify({"ok": False, "message": "Dữ liệu câu hỏi không hợp lệ"}), 400
    conn = db(); old = conn.execute("SELECT id FROM question_bank WHERE id=?", (question_id,)).fetchone()
    if not old:
        conn.close(); return jsonify({"ok": False, "message": "Không tìm thấy câu hỏi"}), 404
    conn.execute(\
        """UPDATE question_bank SET question=?,a=?,b=?,c=?,d=?,correct=?,category=?,difficulty=?,explanation=?,active=?,updated_at=? WHERE id=?""",
        (p["question"],p["a"],p["b"],p["c"],p["d"],p["correct"],p["category"],p["difficulty"],p["explanation"],p["active"],now_text(),question_id)
    )
    conn.commit(); q = conn.execute("SELECT * FROM question_bank WHERE id=?", (question_id,)).fetchone(); conn.close()
    return jsonify({"ok": True, "message": "Đã cập nhật câu hỏi", "question": question_dict(q, True)})


@app.route("/api/questions/<int:question_id>", methods=["DELETE"])
def question_delete_api(question_id):
    actor, err = require_question_manager()
    if err: return err
    conn = db(); q = conn.execute("SELECT id FROM question_bank WHERE id=?", (question_id,)).fetchone()
    if not q:
        conn.close(); return jsonify({"ok": False, "message": "Không tìm thấy câu hỏi"}), 404
    conn.execute("DELETE FROM question_bank WHERE id=?", (question_id,))
    conn.commit(); conn.close()
    return jsonify({"ok": True, "message": "Đã xóa câu hỏi"})



def quiz_set_dict(row):
    try:
        ids = [int(x) for x in json.loads(row["question_ids"] or "[]")]
    except Exception:
        ids = []
    return {
        "id": row["id"], "title": row["title"], "description": row["description"],
        "question_ids": ids, "question_count": len(ids), "active": bool(row["active"]),
        "created_by": row["created_by"], "created_by_name": row["created_by_name"],
        "created_at": row["created_at"], "updated_at": row["updated_at"]
    }


@app.route("/api/quiz-sets", methods=["GET"])
def quiz_sets_list():
    actor = auth_current_user()
    if not actor:
        return jsonify({"ok": False, "message": "Chưa đăng nhập hoặc phiên đã hết hạn"}), 401
    conn = db()
    if actor["role"] in ("admin", "teacher"):
        rows = conn.execute("SELECT * FROM quiz_sets ORDER BY id DESC").fetchall()
    else:
        rows = conn.execute("SELECT * FROM quiz_sets WHERE active=1 ORDER BY title").fetchall()
    result = [quiz_set_dict(r) for r in rows]
    conn.close()
    return jsonify({"ok": True, "quiz_sets": result})


@app.route("/api/quiz-sets", methods=["POST"])
def quiz_set_create_api():
    actor, err = require_question_manager()
    if err: return err
    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()
    description = str(data.get("description", "")).strip()
    raw_ids = data.get("question_ids", [])
    ids = []
    for x in raw_ids if isinstance(raw_ids, list) else []:
        try:
            qid = int(x)
            if qid not in ids: ids.append(qid)
        except Exception:
            pass
    if not title or not ids:
        return jsonify({"ok": False, "message": "Bộ đề phải có tên và ít nhất một câu hỏi"}), 400
    conn = db()
    placeholders = ",".join("?" for _ in ids)
    found = conn.execute(f"SELECT id FROM question_bank WHERE active=1 AND id IN ({placeholders})", ids).fetchall()
    valid = {int(r["id"]) for r in found}
    if any(qid not in valid for qid in ids):
        conn.close(); return jsonify({"ok": False, "message": "Bộ đề chứa câu hỏi không tồn tại hoặc đang tạm ẩn"}), 400
    ts = now_text()
    cur = conn.execute(
        """INSERT INTO quiz_sets(title,description,question_ids,active,created_by,created_by_name,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?)""",
        (title, description, json.dumps(ids), 1 if data.get("active", True) else 0,
         actor["id"], actor["full_name"], ts, ts)
    )
    conn.commit(); row = conn.execute("SELECT * FROM quiz_sets WHERE id=?", (cur.lastrowid,)).fetchone(); conn.close()
    return jsonify({"ok": True, "message": "Đã tạo bộ đề", "quiz_set": quiz_set_dict(row)}), 201


@app.route("/api/quiz-sets/<int:set_id>", methods=["DELETE"])
def quiz_set_delete_api(set_id):
    actor, err = require_question_manager()
    if err: return err
    conn = db(); row = conn.execute("SELECT id FROM quiz_sets WHERE id=?", (set_id,)).fetchone()
    if not row:
        conn.close(); return jsonify({"ok": False, "message": "Không tìm thấy bộ đề"}), 404
    conn.execute("DELETE FROM quiz_sets WHERE id=?", (set_id,)); conn.commit(); conn.close()
    return jsonify({"ok": True, "message": "Đã xóa bộ đề"})


@app.route("/api/station/quiz-sets", methods=["GET"])
def station_quiz_sets():
    if not authorized():
        return jsonify({"ok": False, "message": "Station key không hợp lệ"}), 401
    conn = db(); rows = conn.execute("SELECT * FROM quiz_sets WHERE active=1 ORDER BY title").fetchall()
    result = [quiz_set_dict(r) for r in rows]; conn.close()
    return jsonify({"ok": True, "quiz_sets": result, "server_time": now_text()})


@app.route("/api/station/questions", methods=["GET"])
def station_questions():
    """Trusted training-station download for offline quiz cache."""
    if not authorized():
        return jsonify({"ok": False, "message": "Station key không hợp lệ"}), 401
    conn = db()
    rows = conn.execute("SELECT * FROM question_bank WHERE active=1 ORDER BY category,difficulty,id").fetchall()
    result = [question_dict(x, True) for x in rows]
    conn.close()
    return jsonify({"ok": True, "questions": result, "server_time": now_text()})

@app.route("/api/sync/push", methods=["POST"])
def sync_push():
    if not authorized():
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    station_id = str(data.get("station_id","UNKNOWN"))[:100]
    events = data.get("events", [])
    accepted = []

    conn = db()
    conn.execute("""
      INSERT INTO stations(station_id,last_seen) VALUES(?,?)
      ON CONFLICT(station_id) DO UPDATE SET last_seen=excluded.last_seen
    """, (station_id, now_text()))

    for ev in events:
        event_id = str(ev.get("event_id",""))
        if not event_id:
            continue

        try:
            conn.execute("""
              INSERT INTO sync_events(
                event_id,station_id,event_type,entity_type,entity_id,
                payload,created_at,received_at
              ) VALUES(?,?,?,?,?,?,?,?)
            """, (
                event_id, station_id,
                ev.get("event_type",""),
                ev.get("entity_type",""),
                str(ev.get("entity_id","")),
                json.dumps(ev.get("payload",{}), ensure_ascii=False),
                ev.get("created_at",""),
                now_text()
            ))
        except sqlite3.IntegrityError:
            # Event đã nhận trước đó -> vẫn trả accepted để client kết thúc retry.
            accepted.append(event_id)
            continue

        payload = ev.get("payload", {}) or {}
        entity = ev.get("entity_type","")
        local_id = str(ev.get("entity_id",""))


        if entity == "user_account":
            conn.execute("""
              INSERT INTO users_cloud(station_id,local_id,username,full_name,role,is_active,student_id,updated_at)
              VALUES(?,?,?,?,?,?,?,?)
              ON CONFLICT(station_id,local_id) DO UPDATE SET
                username=excluded.username,full_name=excluded.full_name,role=excluded.role,
                is_active=excluded.is_active,student_id=excluded.student_id,updated_at=excluded.updated_at
            """, (station_id,local_id,payload.get("username",""),payload.get("full_name",""),
                  payload.get("role",""),payload.get("is_active",1),str(payload.get("student_id") or ""),
                  payload.get("updated_at","")))

        elif entity == "class":
            conn.execute("""
              INSERT INTO classes_cloud(station_id,local_id,name,description,updated_at)
              VALUES(?,?,?,?,?)
              ON CONFLICT(station_id,local_id) DO UPDATE SET
                name=excluded.name,description=excluded.description,updated_at=excluded.updated_at
            """, (station_id,local_id,payload.get("name",""),payload.get("description",""),payload.get("updated_at","")))

        elif entity == "student":
            conn.execute("""
              INSERT INTO students_cloud(station_id,local_id,student_code,full_name,class_id,updated_at)
              VALUES(?,?,?,?,?,?)
              ON CONFLICT(station_id,local_id) DO UPDATE SET
                student_code=excluded.student_code,full_name=excluded.full_name,
                class_id=excluded.class_id,updated_at=excluded.updated_at
            """, (station_id,local_id,payload.get("student_code",""),payload.get("full_name",""),
                  str(payload.get("class_id") or ""),payload.get("updated_at","")))

        elif entity == "scenario":
            if ev.get("event_type") == "DELETE":
                conn.execute("DELETE FROM scenarios_cloud WHERE station_id=? AND local_id=?", (station_id, local_id))
            else:
                conn.execute("""
                  INSERT INTO scenarios_cloud(station_id,local_id,name,difficulty,channels,description,updated_at)
                  VALUES(?,?,?,?,?,?,?)
                  ON CONFLICT(station_id,local_id) DO UPDATE SET
                    name=excluded.name,difficulty=excluded.difficulty,channels=excluded.channels,
                    description=excluded.description,updated_at=excluded.updated_at
                """, (station_id,local_id,payload.get("name",""),payload.get("difficulty",""),
                      payload.get("channels",""),payload.get("description",""),payload.get("updated_at","")))

        elif entity == "saved_report":
            if ev.get("event_type") == "DELETE":
                conn.execute("DELETE FROM saved_reports_cloud WHERE station_id=? AND local_id=?", (station_id, local_id))
            else:
                content = payload.get("content_json", {})
                if not isinstance(content, str):
                    content = json.dumps(content, ensure_ascii=False)
                conn.execute("""
                  INSERT INTO saved_reports_cloud(station_id,local_id,title,created_by,created_at,quiz_count,fault_log_count,content_json)
                  VALUES(?,?,?,?,?,?,?,?)
                  ON CONFLICT(station_id,local_id) DO UPDATE SET
                    title=excluded.title,created_by=excluded.created_by,created_at=excluded.created_at,
                    quiz_count=excluded.quiz_count,fault_log_count=excluded.fault_log_count,content_json=excluded.content_json
                """, (station_id,local_id,payload.get("title",""),payload.get("created_by",""),
                      payload.get("created_at",""),payload.get("quiz_count",0),payload.get("fault_log_count",0),content))

        elif entity == "quiz_result":
            conn.execute("""
              INSERT INTO quiz_results_cloud(station_id,local_id,student_name,score,total,created_at)
              VALUES(?,?,?,?,?,?)
              ON CONFLICT(station_id,local_id) DO UPDATE SET
                student_name=excluded.student_name,score=excluded.score,
                total=excluded.total,created_at=excluded.created_at
            """, (station_id,local_id,payload.get("student_name",""),payload.get("score",0),
                  payload.get("total",0),payload.get("created_at","")))

        elif entity == "fault_log":
            conn.execute("""
              INSERT INTO fault_logs_cloud(station_id,local_id,device_code,channel,state,action,actor,created_at)
              VALUES(?,?,?,?,?,?,?,?)
              ON CONFLICT(station_id,local_id) DO UPDATE SET
                device_code=excluded.device_code,channel=excluded.channel,state=excluded.state,
                action=excluded.action,actor=excluded.actor,created_at=excluded.created_at
            """, (station_id,local_id,payload.get("device_code",""),payload.get("channel",0),
                  1 if payload.get("state") else 0,payload.get("action",""),
                  payload.get("actor",""),payload.get("created_at","")))

        accepted.append(event_id)

    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "accepted_event_ids": accepted,
        "received": len(accepted)
    })

@app.route("/")
def dashboard():
    if not CLOUD_PUBLIC_DASHBOARD:
        return render_template_string("""
        <!doctype html><meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>OTO Training Cloud</title>
        <style>
        body{font-family:Segoe UI,Arial;background:#f4f6f8;margin:0;color:#0f172a}
        .card{max-width:700px;margin:10vh auto;background:#fff;border-radius:16px;padding:32px;box-shadow:0 12px 35px #0f172a14}
        .ok{display:inline-block;background:#dcfce7;color:#166534;padding:7px 12px;border-radius:999px;font-weight:700}
        code{background:#f1f5f9;padding:3px 7px;border-radius:6px}
        </style>
        <div class="card">
          <div class="ok">ONLINE</div>
          <h1>OTO Training Cloud</h1>
          <p>Cloud API đang hoạt động. Dùng <code>/api/health</code> để kiểm tra trạng thái dịch vụ.</p>
          <p>Dashboard dữ liệu chi tiết đã được tắt trên môi trường public để tránh lộ thông tin đồng bộ.</p>
        </div>
        """)
    conn = db()
    stations = conn.execute("SELECT * FROM stations ORDER BY last_seen DESC").fetchall()
    counts = {
        "events": conn.execute("SELECT COUNT(*) c FROM sync_events").fetchone()["c"],
        "users": conn.execute("SELECT COUNT(*) c FROM auth_users").fetchone()["c"],
        "classes": conn.execute("SELECT COUNT(*) c FROM classes_cloud").fetchone()["c"],
        "students": conn.execute("SELECT COUNT(*) c FROM students_cloud").fetchone()["c"],
        "questions": conn.execute("SELECT COUNT(*) c FROM question_bank").fetchone()["c"],
        "saved_reports": conn.execute("SELECT COUNT(*) c FROM saved_reports_cloud").fetchone()["c"],
        "quiz": conn.execute("SELECT COUNT(*) c FROM quiz_results_cloud").fetchone()["c"],
        "faults": conn.execute("SELECT COUNT(*) c FROM fault_logs_cloud").fetchone()["c"],
    }
    recent = conn.execute("SELECT * FROM sync_events ORDER BY id DESC LIMIT 30").fetchall()
    conn.close()

    return render_template_string("""
    <!doctype html><meta charset="utf-8">
    <style>
    body{font-family:Segoe UI,Arial;background:#f4f6f8;margin:0;color:#1f2937}
    .wrap{max-width:1100px;margin:30px auto}.card{background:#fff;border-radius:12px;padding:18px;margin-bottom:16px}
    .grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}.n{font-size:30px;font-weight:700;color:#2563eb}
    table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid #e5e7eb;text-align:left}
    </style>
    <div class="wrap">
      <h1>OTO Training Cloud</h1>
      <div class="grid">
        <div class="card">Events<div class="n">{{c.events}}</div></div>
        <div class="card">Tài khoản<div class="n">{{c.users}}</div></div>
        <div class="card">Lớp<div class="n">{{c.classes}}</div></div>
        <div class="card">Học viên<div class="n">{{c.students}}</div></div>
        <div class="card">Câu hỏi<div class="n">{{c.questions}}</div></div>
        <div class="card">Báo cáo lưu<div class="n">{{c.saved_reports}}</div></div>
        <div class="card">Bài thi<div class="n">{{c.quiz}}</div></div>
        <div class="card">Nhật ký lỗi<div class="n">{{c.faults}}</div></div>
      </div>
      <div class="card">
        <h3>Máy trạm</h3>
        <table><tr><th>Station</th><th>Last seen</th></tr>
        {% for s in stations %}<tr><td>{{s.station_id}}</td><td>{{s.last_seen}}</td></tr>{% endfor %}
        </table>
      </div>
      <div class="card">
        <h3>Sự kiện đồng bộ gần nhất</h3>
        <table><tr><th>Station</th><th>Type</th><th>Entity</th><th>Created</th><th>Received</th></tr>
        {% for r in recent %}
        <tr><td>{{r.station_id}}</td><td>{{r.event_type}}</td><td>{{r.entity_type}} #{{r.entity_id}}</td><td>{{r.created_at}}</td><td>{{r.received_at}}</td></tr>
        {% endfor %}
        </table>
      </div>
    </div>
    """, stations=stations, recent=recent, c=counts)

init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"Cloud server: http://127.0.0.1:{port}")
    if not IS_RENDER:
        print("Local demo account: admin / admin123")
        print("Local demo API token: demo-secret-token")
    app.run(host="0.0.0.0", port=port, debug=not IS_RENDER)
