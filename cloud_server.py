"""OTO Training Cloud API - Firebase Firestore backend.

Architecture:
    Desktop App -> Render / Gunicorn / Flask -> Firebase Firestore

The public API is intentionally kept compatible with the previous SQLite cloud
server so the Desktop application does not need to change its routes.
"""

from flask import Flask, request, jsonify, render_template_string
import base64
import datetime
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

import firebase_admin
from firebase_admin import credentials, firestore
from google.api_core.exceptions import AlreadyExists
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken

try:
    from google.cloud.firestore_v1.base_query import FieldFilter
except Exception:  # pragma: no cover - compatibility with older google-cloud-firestore
    FieldFilter = None


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


CLOUD_API_TOKEN = _env_secret("CLOUD_API_TOKEN", "demo-secret-token")
INITIAL_ADMIN_USERNAME = os.environ.get("INITIAL_ADMIN_USERNAME", "admin").strip() or "admin"
INITIAL_ADMIN_PASSWORD = _env_secret("INITIAL_ADMIN_PASSWORD", "admin123")
CLOUD_SESSION_HOURS = max(1, int(os.environ.get("CLOUD_SESSION_HOURS", "12")))
CLOUD_PUBLIC_DASHBOARD = os.environ.get(
    "CLOUD_PUBLIC_DASHBOARD", "false" if IS_RENDER else "true"
).strip().lower() in ("1", "true", "yes", "on")
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "").strip()

# Opportunistic Firestore session cleanup. This runs inside the existing Render
# service, so it does not require Firebase Cloud Functions / Blaze. Expired
# tokens are queried by expires_at and removed in small batches.
AUTH_TOKEN_CLEANUP_INTERVAL_SEC = max(60, int(os.environ.get("AUTH_TOKEN_CLEANUP_INTERVAL_SEC", "600")))
AUTH_TOKEN_CLEANUP_BATCH_SIZE = min(450, max(1, int(os.environ.get("AUTH_TOKEN_CLEANUP_BATCH_SIZE", "200"))))

if IS_RENDER and len(INITIAL_ADMIN_PASSWORD) < 8:
    raise RuntimeError("INITIAL_ADMIN_PASSWORD trên Render phải có ít nhất 8 ký tự.")
if IS_RENDER and len(CLOUD_API_TOKEN) < 16:
    raise RuntimeError("CLOUD_API_TOKEN trên Render phải có ít nhất 16 ký tự.")


app = Flask(__name__)
CLOUD_BUILD_VERSION = "2026.09.26-mqtt-config-cloud-v2"
_firestore_db = None
_token_cleanup_lock = threading.Lock()
_last_token_cleanup_monotonic = 0.0


# =========================================================
# FIREBASE / FIRESTORE INITIALIZATION
# =========================================================
def _service_account_info():
    """Load a Firebase service-account from one of the supported sources.

    Preferred on Render:
      FIREBASE_SERVICE_ACCOUNT_B64=<base64 of service-account JSON>

    Other supported forms:
      FIREBASE_SERVICE_ACCOUNT_JSON=<raw JSON>
      FIREBASE_SERVICE_ACCOUNT_FILE=/path/to/file.json
      ./firebase-service-account.json (local development only)
      GOOGLE_APPLICATION_CREDENTIALS / Application Default Credentials
    """
    raw_b64 = os.environ.get("FIREBASE_SERVICE_ACCOUNT_B64", "").strip()
    if raw_b64:
        try:
            decoded = base64.b64decode(raw_b64).decode("utf-8")
            return json.loads(decoded)
        except Exception as exc:
            raise RuntimeError("FIREBASE_SERVICE_ACCOUNT_B64 không hợp lệ.") from exc

    raw_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
    if raw_json:
        try:
            return json.loads(raw_json)
        except Exception as exc:
            raise RuntimeError("FIREBASE_SERVICE_ACCOUNT_JSON không phải JSON hợp lệ.") from exc

    explicit_file = os.environ.get("FIREBASE_SERVICE_ACCOUNT_FILE", "").strip()
    if explicit_file:
        path = explicit_file
        if not os.path.isabs(path):
            path = os.path.join(BASE_DIR, path)
        if not os.path.isfile(path):
            raise RuntimeError(f"Không tìm thấy FIREBASE_SERVICE_ACCOUNT_FILE: {path}")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    local_file = os.path.join(BASE_DIR, "firebase-service-account.json")
    if os.path.isfile(local_file):
        with open(local_file, "r", encoding="utf-8") as f:
            return json.load(f)

    return None


def init_firebase():
    global _firestore_db
    if _firestore_db is not None:
        return _firestore_db

    try:
        fb_app = firebase_admin.get_app()
    except ValueError:
        info = _service_account_info()
        options = {"projectId": FIREBASE_PROJECT_ID} if FIREBASE_PROJECT_ID else None

        if info:
            cred = credentials.Certificate(info)
            fb_app = firebase_admin.initialize_app(cred, options=options)
        else:
            # Useful when running on Google Cloud / Cloud Run with ADC.
            # On Render, configure FIREBASE_SERVICE_ACCOUNT_B64.
            try:
                cred = credentials.ApplicationDefault()
                fb_app = firebase_admin.initialize_app(cred, options=options)
            except Exception as exc:
                raise RuntimeError(
                    "Thiếu Firebase credentials. Trên Render hãy cấu hình "
                    "FIREBASE_SERVICE_ACCOUNT_B64 (khuyến nghị), hoặc "
                    "FIREBASE_SERVICE_ACCOUNT_JSON / FIREBASE_SERVICE_ACCOUNT_FILE."
                ) from exc

    _firestore_db = firestore.client(app=fb_app)
    return _firestore_db


def fdb():
    return init_firebase()


def col(name):
    return fdb().collection(name)


def _where_eq(collection_ref, field, value):
    if FieldFilter is not None:
        return collection_ref.where(filter=FieldFilter(field, "==", value))
    return collection_ref.where(field, "==", value)


def _where_lte(collection_ref, field, value):
    if FieldFilter is not None:
        return collection_ref.where(filter=FieldFilter(field, "<=", value))
    return collection_ref.where(field, "<=", value)


def first_where(collection_name, field, value):
    docs = _where_eq(col(collection_name), field, value).limit(1).stream()
    for snap in docs:
        data = snap.to_dict() or {}
        data["_doc_id"] = snap.id
        return data
    return None


def get_by_numeric_id(collection_name, numeric_id):
    snap = col(collection_name).document(str(int(numeric_id))).get()
    if not snap.exists:
        return None
    data = snap.to_dict() or {}
    data["_doc_id"] = snap.id
    return data


def all_docs(collection_name):
    result = []
    for snap in col(collection_name).stream():
        data = snap.to_dict() or {}
        data["_doc_id"] = snap.id
        result.append(data)
    return result


def _new_numeric_id():
    # 16-digit positive integer, within Firestore / SQLite signed 64-bit range.
    return int(time.time() * 1_000_000) + secrets.randbelow(1000)


def create_numeric_doc(collection_name, data):
    collection_ref = col(collection_name)
    for _ in range(20):
        numeric_id = _new_numeric_id()
        payload = dict(data)
        payload["id"] = numeric_id
        ref = collection_ref.document(str(numeric_id))
        try:
            ref.create(payload)
            return payload
        except AlreadyExists:
            continue
    raise RuntimeError(f"Không tạo được ID duy nhất cho collection {collection_name}.")


def safe_doc_id(*parts):
    raw = "\x1f".join(str(x) for x in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()



def _mqtt_config_fernet():
    """Return a stable Fernet instance for MQTT password encryption at rest.

    If MQTT_CONFIG_ENCRYPTION_KEY is configured, it must be a valid Fernet key.
    Otherwise a deterministic key is derived from CLOUD_API_TOKEN so existing
    deployments do not require an extra environment variable.
    """
    raw = os.environ.get("MQTT_CONFIG_ENCRYPTION_KEY", "").strip()
    if raw:
        try:
            return Fernet(raw.encode("utf-8"))
        except Exception as exc:
            raise RuntimeError(
                "MQTT_CONFIG_ENCRYPTION_KEY không hợp lệ. "
                "Hãy dùng khóa Fernet URL-safe base64."
            ) from exc

    derived = hashlib.sha256(
        (CLOUD_API_TOKEN + "|oto-mqtt-config-v1").encode("utf-8")
    ).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_mqtt_password(value):
    value = str(value or "")
    if not value:
        return ""
    return _mqtt_config_fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_mqtt_password(value):
    value = str(value or "")
    if not value:
        return ""
    try:
        return _mqtt_config_fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError(
            "Không giải mã được MQTT password đã lưu. "
            "Khóa mã hóa Cloud có thể đã thay đổi."
        ) from exc


def mqtt_config_public_dict(row):
    row = dict(row or {})
    return {
        "station_id": str(row.get("station_id") or ""),
        "device_control_mode": str(row.get("device_control_mode") or "mqtt"),
        "mqtt_host": str(row.get("mqtt_host") or ""),
        "mqtt_port": int(row.get("mqtt_port") or 8883),
        "mqtt_username": str(row.get("mqtt_username") or ""),
        "mqtt_password": decrypt_mqtt_password(row.get("mqtt_password_enc") or ""),
        "mqtt_tls": bool(row.get("mqtt_tls", True)),
        "device_command_timeout_sec": float(row.get("device_command_timeout_sec") or 5.0),
        "updated_at": str(row.get("updated_at") or ""),
    }

def now_text():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in ("1", "true", "yes", "on")


# =========================================================
# INITIAL DATA
# =========================================================
def init_db():
    """Initialize Firestore collections and seed the initial admin/questions."""
    fdb()  # fail early when Firebase configuration is invalid

    admin = first_where("auth_users", "username", INITIAL_ADMIN_USERNAME)
    if not admin:
        ts = now_text()
        create_numeric_doc("auth_users", {
            "username": INITIAL_ADMIN_USERNAME,
            "password_hash": generate_password_hash(INITIAL_ADMIN_PASSWORD),
            "full_name": "Quản trị viên",
            "role": "admin",
            "active": True,
            "student_code": None,
            "class_id": None,
            "created_by": None,
            "created_at": ts,
            "updated_at": ts,
        })

    # Seed sample questions only when the central bank is completely empty.
    if not next(iter(col("question_bank").limit(1).stream()), None):
        ts = now_text()
        samples = [
            ("Điện áp danh định của ắc quy ô tô con thông dụng là bao nhiêu?", "6V", "12V", "24V", "48V", "B", "Điện ô tô", "Cơ bản", "Ắc quy ô tô con thông dụng có điện áp danh định 12 V."),
            ("Cảm biến CKP dùng để xác định chủ yếu thông tin nào?", "Áp suất nhiên liệu", "Nhiệt độ nước", "Vị trí/tốc độ trục khuỷu", "Mức nhiên liệu", "C", "Động cơ", "Cơ bản", "CKP cung cấp thông tin vị trí và tốc độ trục khuỷu."),
            ("Khi kiểm tra mạch điện, thao tác nào nên thực hiện trước?", "Thay ECU ngay", "Kiểm tra nguồn và mass", "Cắt dây thử", "Thay toàn bộ cảm biến", "B", "Chẩn đoán", "Cơ bản", "Nguồn và mass là các điều kiện nền tảng cần xác nhận trước."),
        ]
        for q in samples:
            create_numeric_doc("question_bank", {
                "question": q[0], "a": q[1], "b": q[2], "c": q[3], "d": q[4],
                "correct": q[5], "category": q[6], "difficulty": q[7],
                "explanation": q[8], "active": True,
                "created_by": None, "created_by_name": "system",
                "created_at": ts, "updated_at": ts,
            })


def cleanup_expired_auth_tokens(limit=None):
    """Delete expired session documents from Firestore.

    Returns the number of deleted token documents. The query is bounded so one
    normal API request never spends too long cleaning old sessions.
    """
    max_docs = AUTH_TOKEN_CLEANUP_BATCH_SIZE if limit is None else min(450, max(1, int(limit)))
    now = utc_now()
    query = _where_lte(col("auth_tokens"), "expires_at", now).limit(max_docs)
    expired = list(query.stream())
    if not expired:
        return 0

    batch = fdb().batch()
    for snap in expired:
        batch.delete(snap.reference)
    batch.commit()
    return len(expired)


def maybe_cleanup_expired_auth_tokens(force=False):
    """Run a throttled token cleanup without making normal requests fail.

    Render Free can sleep, so a permanent background scheduler is not reliable.
    Instead, the first API request after each cleanup interval performs a small
    sweep. This also means expired tokens are cleaned shortly after the service
    wakes up again.
    """
    global _last_token_cleanup_monotonic

    now_mono = time.monotonic()
    if not force and (now_mono - _last_token_cleanup_monotonic) < AUTH_TOKEN_CLEANUP_INTERVAL_SEC:
        return 0

    if not _token_cleanup_lock.acquire(blocking=False):
        return 0

    try:
        now_mono = time.monotonic()
        if not force and (now_mono - _last_token_cleanup_monotonic) < AUTH_TOKEN_CLEANUP_INTERVAL_SEC:
            return 0

        deleted = cleanup_expired_auth_tokens()
        _last_token_cleanup_monotonic = time.monotonic()
        if deleted:
            app.logger.info("Deleted %s expired auth token(s) from Firestore", deleted)
        return deleted
    except Exception:
        # Cleanup is maintenance work; it must never make the API unavailable.
        app.logger.exception("Expired auth token cleanup failed")
        _last_token_cleanup_monotonic = time.monotonic()
        return 0
    finally:
        _token_cleanup_lock.release()


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


@app.before_request
def maintenance_before_request():
    # Only API traffic needs to trigger maintenance. The call is throttled and
    # non-blocking across Gunicorn threads.
    if request.path.startswith("/api/"):
        maybe_cleanup_expired_auth_tokens()


@app.route("/api/health")
def api_health():
    try:
        # Small read to verify Firestore connectivity without creating data.
        next(iter(col("auth_users").limit(1).stream()), None)
        return jsonify({
            "ok": True,
            "service": "OTO Training Cloud",
            "server_time": now_text(),
            "database": "firestore",
            "firebase_project": FIREBASE_PROJECT_ID or "configured-by-service-account",
            "build_version": CLOUD_BUILD_VERSION,
            "capabilities": ["account_delete_v2", "mqtt_config_cloud_v2"],
        })
    except Exception as exc:
        app.logger.exception("Firestore health check failed")
        return jsonify({
            "ok": False,
            "service": "OTO Training Cloud",
            "database": "firestore-error",
            "message": str(exc)[:300],
        }), 503


# =========================================================
# CLOUD AUTH
# =========================================================
def auth_current_user():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    token = h[7:].strip()
    if not token:
        return None

    th = token_hash(token)
    token_ref = col("auth_tokens").document(th)
    snap = token_ref.get()
    if not snap.exists:
        return None

    session_data = snap.to_dict() or {}
    expires_at = session_data.get("expires_at")
    if isinstance(expires_at, datetime.datetime):
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        if expires_at <= utc_now():
            token_ref.delete()
            return None
    else:
        token_ref.delete()
        return None

    user_id = session_data.get("user_id")
    if user_id is None:
        token_ref.delete()
        return None

    user = get_by_numeric_id("auth_users", int(user_id))
    if not user or not _as_bool(user.get("active", False)):
        token_ref.delete()
        return None
    return user


def auth_can_manage(actor_role, target_role):
    if actor_role == "admin":
        return target_role in ("teacher", "student")
    if actor_role == "teacher":
        return target_role == "student"
    return False


def auth_user_dict(u):
    return {
        "id": u.get("id"),
        "username": u.get("username", ""),
        "full_name": u.get("full_name", ""),
        "role": u.get("role", "student"),
        "active": _as_bool(u.get("active", False)),
        "student_code": u.get("student_code"),
        "class_id": u.get("class_id"),
        "updated_at": u.get("updated_at", ""),
    }


@app.route("/api/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    u = first_where("auth_users", "username", username)

    if not u or not check_password_hash(u.get("password_hash", ""), password):
        return jsonify({"ok": False, "message": "Sai tài khoản hoặc mật khẩu"}), 401
    if not _as_bool(u.get("active", False)):
        return jsonify({"ok": False, "message": "Tài khoản đã bị khóa"}), 403

    token = secrets.token_hex(32)
    created_at = utc_now()
    expires_at = created_at + datetime.timedelta(hours=CLOUD_SESSION_HOURS)
    col("auth_tokens").document(token_hash(token)).set({
        "user_id": int(u["id"]),
        "created_at": created_at,
        "expires_at": expires_at,
    })

    return jsonify({
        "ok": True,
        "token": token,
        "expires_in_seconds": CLOUD_SESSION_HOURS * 3600,
        "user": auth_user_dict(u),
    })


@app.route("/api/logout", methods=["POST"])
def auth_logout():
    h = request.headers.get("Authorization", "")
    if h.startswith("Bearer "):
        raw = h[7:].strip()
        if raw:
            col("auth_tokens").document(token_hash(raw)).delete()
    return jsonify({"ok": True})


@app.route("/api/users", methods=["GET"])
def auth_users_list():
    actor = auth_current_user()
    if not actor:
        return jsonify({"ok": False, "message": "Chưa đăng nhập hoặc phiên đã hết hạn"}), 401
    if actor.get("role") not in ("admin", "teacher"):
        return jsonify({"ok": False, "message": "Không có quyền"}), 403

    rows = all_docs("auth_users")
    if actor.get("role") == "admin":
        rows = [x for x in rows if x.get("role") in ("teacher", "student")]
        rows.sort(key=lambda x: (0 if x.get("role") == "teacher" else 1, -int(x.get("id", 0))))
    else:
        rows = [x for x in rows if x.get("role") == "student"]
        rows.sort(key=lambda x: -int(x.get("id", 0)))
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

    if not auth_can_manage(actor.get("role"), role):
        return jsonify({"ok": False, "message": "Bạn không có quyền tạo loại tài khoản này"}), 403
    if len(username) < 3 or len(password) < 6 or not full_name:
        return jsonify({"ok": False, "message": "Tên đăng nhập tối thiểu 3 ký tự, mật khẩu tối thiểu 6 ký tự"}), 400
    if role == "student" and not student_code:
        student_code = username.upper()

    if first_where("auth_users", "username", username):
        return jsonify({"ok": False, "message": "Tên đăng nhập đã tồn tại"}), 409
    if student_code and first_where("auth_users", "student_code", student_code):
        return jsonify({"ok": False, "message": "Mã sinh viên đã tồn tại"}), 409

    ts = now_text()
    u = create_numeric_doc("auth_users", {
        "username": username,
        "password_hash": generate_password_hash(password),
        "full_name": full_name,
        "role": role,
        "active": True,
        "student_code": student_code if role == "student" else None,
        "class_id": class_id if role == "student" else None,
        "created_by": actor.get("id"),
        "created_at": ts,
        "updated_at": ts,
    })
    return jsonify({"ok": True, "message": "Tạo tài khoản thành công", "user": auth_user_dict(u)}), 201


@app.route("/api/users/<int:user_id>/active", methods=["PUT"])
def auth_user_active(user_id):
    actor = auth_current_user()
    if not actor:
        return jsonify({"ok": False, "message": "Chưa đăng nhập"}), 401
    data = request.get_json(silent=True) or {}
    target = get_by_numeric_id("auth_users", user_id)
    if not target:
        return jsonify({"ok": False, "message": "Không tìm thấy tài khoản"}), 404
    if not auth_can_manage(actor.get("role"), target.get("role")):
        return jsonify({"ok": False, "message": "Không có quyền"}), 403

    ref = col("auth_users").document(str(user_id))
    ref.update({"active": bool(data.get("active")), "updated_at": now_text()})
    target = get_by_numeric_id("auth_users", user_id)
    return jsonify({"ok": True, "user": auth_user_dict(target)})


def _delete_auth_user_impl(user_id):
    actor = auth_current_user()
    if not actor:
        return jsonify({"ok": False, "message": "Chưa đăng nhập hoặc phiên đã hết hạn"}), 401

    target = get_by_numeric_id("auth_users", user_id)
    if not target:
        return jsonify({"ok": False, "message": "Không tìm thấy tài khoản trên Cloud"}), 404

    # Admin quản lý/xóa Giáo viên và Sinh viên.
    # Giáo viên chỉ quản lý/xóa Sinh viên.
    if not auth_can_manage(actor.get("role"), target.get("role")):
        return jsonify({"ok": False, "message": "Bạn không có quyền xóa tài khoản này"}), 403

    # Không cho xóa chính tài khoản đang đăng nhập nếu sau này admin được hiển thị trong list.
    try:
        if int(actor.get("id", -1)) == int(user_id):
            return jsonify({"ok": False, "message": "Không thể xóa chính tài khoản đang đăng nhập"}), 400
    except Exception:
        pass

    deleted_user = auth_user_dict(target)

    try:
        # Thu hồi mọi phiên đăng nhập của user trước khi xóa account.
        revoked_tokens = 0
        for snap in col("auth_tokens").stream():
            token_data = snap.to_dict() or {}
            try:
                token_user_id = int(token_data.get("user_id", -1))
            except Exception:
                token_user_id = -1
            if token_user_id == int(user_id):
                snap.reference.delete()
                revoked_tokens += 1

        # Xóa account khỏi Firestore Cloud.
        user_ref = col("auth_users").document(str(int(user_id)))
        user_ref.delete()

        # Verify trực tiếp sau delete. Chỉ báo thành công khi document thực sự không còn.
        verify = user_ref.get()
        if verify.exists:
            app.logger.error("Cloud account delete verification failed for user_id=%s", user_id)
            return jsonify({
                "ok": False,
                "message": "Cloud đã nhận lệnh nhưng xác minh xóa tài khoản thất bại",
            }), 500

        return jsonify({
            "ok": True,
            "message": "Đã xóa tài khoản trên Cloud",
            "cloud_deleted": True,
            "revoked_tokens": revoked_tokens,
            "user": deleted_user,
            "build_version": CLOUD_BUILD_VERSION,
        }), 200
    except Exception as exc:
        app.logger.exception("Delete Cloud account failed: user_id=%s", user_id)
        return jsonify({
            "ok": False,
            "message": "Lỗi khi xóa tài khoản trên Cloud: " + str(exc)[:220],
        }), 500


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def auth_user_delete(user_id):
    return _delete_auth_user_impl(user_id)


@app.route("/api/users/<int:user_id>/delete", methods=["POST"])
def auth_user_delete_post(user_id):
    # Endpoint POST riêng giúp Desktop hoạt động ổn định qua reverse proxy/PaaS
    # và dễ phân biệt với route PATCH cùng URL.
    return _delete_auth_user_impl(user_id)


@app.route("/api/users/<int:user_id>", methods=["PATCH"])
def auth_user_update(user_id):
    actor = auth_current_user()
    if not actor:
        return jsonify({"ok": False, "message": "Chưa đăng nhập"}), 401
    data = request.get_json(silent=True) or {}
    target = get_by_numeric_id("auth_users", user_id)
    if not target:
        return jsonify({"ok": False, "message": "Không tìm thấy tài khoản"}), 404
    if not auth_can_manage(actor.get("role"), target.get("role")):
        return jsonify({"ok": False, "message": "Không có quyền"}), 403

    full_name = str(data.get("full_name", target.get("full_name", ""))).strip() or target.get("full_name", "")
    student_code = target.get("student_code")
    class_id = target.get("class_id")

    if target.get("role") == "student":
        student_code = str(data.get("student_code", student_code) or "").strip() or str(target.get("username", "")).upper()
        class_id = str(data.get("class_id") or "").strip() or None
        dup = first_where("auth_users", "student_code", student_code)
        if dup and int(dup.get("id", -1)) != int(user_id):
            return jsonify({"ok": False, "message": "Mã sinh viên đã tồn tại"}), 409

    updates = {
        "full_name": full_name,
        "student_code": student_code,
        "class_id": class_id,
        "updated_at": now_text(),
    }
    new_password = str(data.get("new_password") or "")
    if new_password:
        if len(new_password) < 6:
            return jsonify({"ok": False, "message": "Mật khẩu mới tối thiểu 6 ký tự"}), 400
        updates["password_hash"] = generate_password_hash(new_password)

    col("auth_users").document(str(user_id)).update(updates)
    target = get_by_numeric_id("auth_users", user_id)
    return jsonify({"ok": True, "user": auth_user_dict(target)})


# =========================================================
# CENTRAL QUESTION BANK
# =========================================================
def question_dict(q, include_answer=True):
    data = {
        "id": q.get("id"),
        "question": q.get("question", ""),
        "a": q.get("a", ""), "b": q.get("b", ""), "c": q.get("c", ""), "d": q.get("d", ""),
        "category": q.get("category", "Chung"),
        "difficulty": q.get("difficulty", "Cơ bản"),
        "active": _as_bool(q.get("active", True)),
        "created_by": q.get("created_by"),
        "created_by_name": q.get("created_by_name", ""),
        "created_at": q.get("created_at", ""),
        "updated_at": q.get("updated_at", ""),
    }
    if include_answer:
        data["correct"] = q.get("correct", "A")
        data["explanation"] = q.get("explanation", "")
    return data


def require_question_manager():
    actor = auth_current_user()
    if not actor:
        return None, (jsonify({"ok": False, "message": "Chưa đăng nhập hoặc phiên đã hết hạn"}), 401)
    if actor.get("role") not in ("admin", "teacher"):
        return None, (jsonify({"ok": False, "message": "Không có quyền quản lý câu hỏi"}), 403)
    return actor, None


@app.route("/api/questions", methods=["GET"])
def questions_list():
    actor = auth_current_user()
    if not actor:
        return jsonify({"ok": False, "message": "Chưa đăng nhập hoặc phiên đã hết hạn"}), 401
    rows = all_docs("question_bank")
    if actor.get("role") in ("admin", "teacher"):
        rows.sort(key=lambda x: (str(x.get("category", "")), str(x.get("difficulty", "")), -int(x.get("id", 0))))
        result = [question_dict(x, True) for x in rows]
    else:
        rows = [x for x in rows if _as_bool(x.get("active", True))]
        rows.sort(key=lambda x: (str(x.get("category", "")), str(x.get("difficulty", "")), int(x.get("id", 0))))
        result = [question_dict(x, False) for x in rows]
    return jsonify({"ok": True, "questions": result})


@app.route("/api/questions/<int:question_id>", methods=["GET"])
def question_get(question_id):
    actor, err = require_question_manager()
    if err:
        return err
    q = get_by_numeric_id("question_bank", question_id)
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
        "active": bool(data.get("active", True)),
    }


@app.route("/api/questions", methods=["POST"])
def question_create_api():
    actor, err = require_question_manager()
    if err:
        return err
    p = question_payload(request.get_json(silent=True) or {})
    if not all(p[k] for k in ("question", "a", "b", "c", "d")) or p["correct"] not in ("A", "B", "C", "D"):
        return jsonify({"ok": False, "message": "Dữ liệu câu hỏi không hợp lệ"}), 400

    ts = now_text()
    q = create_numeric_doc("question_bank", {
        **p,
        "created_by": actor.get("id"),
        "created_by_name": actor.get("full_name", ""),
        "created_at": ts,
        "updated_at": ts,
    })
    return jsonify({"ok": True, "message": "Đã thêm câu hỏi", "question": question_dict(q, True)}), 201


@app.route("/api/questions/<int:question_id>", methods=["PUT"])
def question_update_api(question_id):
    actor, err = require_question_manager()
    if err:
        return err
    p = question_payload(request.get_json(silent=True) or {})
    if not all(p[k] for k in ("question", "a", "b", "c", "d")) or p["correct"] not in ("A", "B", "C", "D"):
        return jsonify({"ok": False, "message": "Dữ liệu câu hỏi không hợp lệ"}), 400

    old = get_by_numeric_id("question_bank", question_id)
    if not old:
        return jsonify({"ok": False, "message": "Không tìm thấy câu hỏi"}), 404
    col("question_bank").document(str(question_id)).update({**p, "updated_at": now_text()})
    q = get_by_numeric_id("question_bank", question_id)
    return jsonify({"ok": True, "message": "Đã cập nhật câu hỏi", "question": question_dict(q, True)})


@app.route("/api/questions/<int:question_id>", methods=["DELETE"])
def question_delete_api(question_id):
    actor, err = require_question_manager()
    if err:
        return err
    q = get_by_numeric_id("question_bank", question_id)
    if not q:
        return jsonify({"ok": False, "message": "Không tìm thấy câu hỏi"}), 404
    col("question_bank").document(str(question_id)).delete()
    return jsonify({"ok": True, "message": "Đã xóa câu hỏi"})


# =========================================================
# QUIZ SETS
# =========================================================
def quiz_set_dict(row):
    raw = row.get("question_ids", [])
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "[]")
        except Exception:
            raw = []
    ids = []
    for x in raw if isinstance(raw, list) else []:
        try:
            ids.append(int(x))
        except Exception:
            pass
    return {
        "id": row.get("id"),
        "title": row.get("title", ""),
        "description": row.get("description", ""),
        "question_ids": ids,
        "question_count": len(ids),
        "active": _as_bool(row.get("active", True)),
        "created_by": row.get("created_by"),
        "created_by_name": row.get("created_by_name", ""),
        "created_at": row.get("created_at", ""),
        "updated_at": row.get("updated_at", ""),
    }


@app.route("/api/quiz-sets", methods=["GET"])
def quiz_sets_list():
    actor = auth_current_user()
    if not actor:
        return jsonify({"ok": False, "message": "Chưa đăng nhập hoặc phiên đã hết hạn"}), 401
    rows = all_docs("quiz_sets")
    if actor.get("role") in ("admin", "teacher"):
        rows.sort(key=lambda x: -int(x.get("id", 0)))
    else:
        rows = [x for x in rows if _as_bool(x.get("active", True))]
        rows.sort(key=lambda x: str(x.get("title", "")))
    return jsonify({"ok": True, "quiz_sets": [quiz_set_dict(r) for r in rows]})


@app.route("/api/quiz-sets", methods=["POST"])
def quiz_set_create_api():
    actor, err = require_question_manager()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()
    description = str(data.get("description", "")).strip()
    raw_ids = data.get("question_ids", [])
    ids = []
    for x in raw_ids if isinstance(raw_ids, list) else []:
        try:
            qid = int(x)
            if qid not in ids:
                ids.append(qid)
        except Exception:
            pass
    if not title or not ids:
        return jsonify({"ok": False, "message": "Bộ đề phải có tên và ít nhất một câu hỏi"}), 400

    for qid in ids:
        q = get_by_numeric_id("question_bank", qid)
        if not q or not _as_bool(q.get("active", True)):
            return jsonify({"ok": False, "message": "Bộ đề chứa câu hỏi không tồn tại hoặc đang tạm ẩn"}), 400

    ts = now_text()
    row = create_numeric_doc("quiz_sets", {
        "title": title,
        "description": description,
        "question_ids": ids,
        "active": bool(data.get("active", True)),
        "created_by": actor.get("id"),
        "created_by_name": actor.get("full_name", ""),
        "created_at": ts,
        "updated_at": ts,
    })
    return jsonify({"ok": True, "message": "Đã tạo bộ đề", "quiz_set": quiz_set_dict(row)}), 201


@app.route("/api/quiz-sets/<int:set_id>", methods=["DELETE"])
def quiz_set_delete_api(set_id):
    actor, err = require_question_manager()
    if err:
        return err
    row = get_by_numeric_id("quiz_sets", set_id)
    if not row:
        return jsonify({"ok": False, "message": "Không tìm thấy bộ đề"}), 404
    col("quiz_sets").document(str(set_id)).delete()
    return jsonify({"ok": True, "message": "Đã xóa bộ đề"})


@app.route("/api/station/quiz-sets", methods=["GET"])
def station_quiz_sets():
    if not authorized():
        return jsonify({"ok": False, "message": "Station key không hợp lệ"}), 401
    rows = [x for x in all_docs("quiz_sets") if _as_bool(x.get("active", True))]
    rows.sort(key=lambda x: str(x.get("title", "")))
    return jsonify({"ok": True, "quiz_sets": [quiz_set_dict(r) for r in rows], "server_time": now_text()})


@app.route("/api/station/questions", methods=["GET"])
def station_questions():
    """Trusted training-station download for offline quiz cache."""
    if not authorized():
        return jsonify({"ok": False, "message": "Station key không hợp lệ"}), 401
    rows = [x for x in all_docs("question_bank") if _as_bool(x.get("active", True))]
    rows.sort(key=lambda x: (str(x.get("category", "")), str(x.get("difficulty", "")), int(x.get("id", 0))))
    return jsonify({"ok": True, "questions": [question_dict(x, True) for x in rows], "server_time": now_text()})



# =========================================================
# STATION DEVICE / MQTT CONFIG
# =========================================================
def mqtt_config_access_allowed():
    """Allow trusted station API key OR authenticated Admin/Teacher."""
    if authorized():
        return True, None
    actor = auth_current_user()
    if actor and actor.get("role") in ("admin", "teacher"):
        return True, actor
    return False, actor


@app.route("/api/station/mqtt-config/get", methods=["POST"])
def station_mqtt_config_get():
    allowed, actor = mqtt_config_access_allowed()
    if not allowed:
        return jsonify({"ok": False, "message": "Không có quyền đọc cấu hình MQTT Cloud"}), 401

    data = request.get_json(silent=True) or {}
    station_id = str(data.get("station_id") or "").strip()
    if not station_id:
        return jsonify({"ok": False, "message": "Thiếu station_id"}), 400

    snap = col("station_mqtt_configs").document(safe_doc_id(station_id)).get()
    if not snap.exists:
        return jsonify({
            "ok": False,
            "message": "Station chưa có cấu hình MQTT trên Cloud",
            "station_id": station_id,
        }), 404

    row = snap.to_dict() or {}
    try:
        cfg = mqtt_config_public_dict(row)
    except Exception as exc:
        app.logger.exception("Failed to decrypt MQTT config for station %s", station_id)
        return jsonify({
            "ok": False,
            "message": f"Không đọc được cấu hình MQTT trên Cloud: {exc}",
        }), 500

    return jsonify({
        "ok": True,
        "config": cfg,
        "server_time": now_text(),
    })


@app.route("/api/station/mqtt-config/save", methods=["POST"])
def station_mqtt_config_save():
    allowed, actor = mqtt_config_access_allowed()
    if not allowed:
        return jsonify({"ok": False, "message": "Không có quyền lưu cấu hình MQTT Cloud"}), 401

    data = request.get_json(silent=True) or {}
    station_id = str(data.get("station_id") or "").strip()
    cfg = data.get("config") or {}

    if not station_id:
        return jsonify({"ok": False, "message": "Thiếu station_id"}), 400
    if not isinstance(cfg, dict):
        return jsonify({"ok": False, "message": "config không hợp lệ"}), 400

    mode = str(cfg.get("device_control_mode") or "mqtt").strip().lower()
    if mode not in ("simulation", "serial", "mqtt"):
        mode = "mqtt"

    host = str(cfg.get("mqtt_host") or "").strip()
    username = str(cfg.get("mqtt_username") or "").strip()
    password = str(cfg.get("mqtt_password") or "")

    try:
        port = int(cfg.get("mqtt_port") or 8883)
    except Exception:
        port = 8883
    port = max(1, min(port, 65535))

    try:
        timeout = float(cfg.get("device_command_timeout_sec") or 5.0)
    except Exception:
        timeout = 5.0
    timeout = max(1.0, min(timeout, 20.0))

    ref = col("station_mqtt_configs").document(safe_doc_id(station_id))
    old = ref.get()
    old_data = old.to_dict() if old.exists else {}

    # Empty password means "keep old Cloud password" when a record already exists.
    if password:
        password_enc = encrypt_mqtt_password(password)
    else:
        password_enc = str((old_data or {}).get("mqtt_password_enc") or "")

    saved_at = now_text()
    row = {
        "station_id": station_id,
        "device_control_mode": mode,
        "mqtt_host": host,
        "mqtt_port": port,
        "mqtt_username": username,
        "mqtt_password_enc": password_enc,
        "mqtt_tls": bool(cfg.get("mqtt_tls", True)),
        "device_command_timeout_sec": timeout,
        "updated_at": saved_at,
        "updated_by": (actor.get("username") if actor else "station-api"),
    }
    ref.set(row)

    return jsonify({
        "ok": True,
        "message": "Đã lưu cấu hình MQTT lên Cloud",
        "station_id": station_id,
        "updated_at": saved_at,
    })


# =========================================================
# DESKTOP -> CLOUD SYNC
# =========================================================
def _upsert_cloud_entity(batch, entity, station_id, local_id, payload, event_type):
    collection_map = {
        "user_account": "users_cloud",
        "class": "classes_cloud",
        "student": "students_cloud",
        "scenario": "scenarios_cloud",
        "saved_report": "saved_reports_cloud",
        "quiz_result": "quiz_results_cloud",
        "fault_log": "fault_logs_cloud",
    }
    collection_name = collection_map.get(entity)
    if not collection_name:
        return

    ref = col(collection_name).document(safe_doc_id(station_id, local_id))
    if event_type == "DELETE" and entity in ("scenario", "saved_report"):
        batch.delete(ref)
        return

    common = {
        "station_id": station_id,
        "local_id": str(local_id),
    }

    if entity == "user_account":
        doc = {
            **common,
            "username": payload.get("username", ""),
            "full_name": payload.get("full_name", ""),
            "role": payload.get("role", ""),
            "is_active": bool(payload.get("is_active", 1)),
            "student_id": str(payload.get("student_id") or ""),
            "updated_at": payload.get("updated_at", ""),
        }
    elif entity == "class":
        doc = {
            **common,
            "name": payload.get("name", ""),
            "description": payload.get("description", ""),
            "updated_at": payload.get("updated_at", ""),
        }
    elif entity == "student":
        doc = {
            **common,
            "student_code": payload.get("student_code", ""),
            "full_name": payload.get("full_name", ""),
            "class_id": str(payload.get("class_id") or ""),
            "updated_at": payload.get("updated_at", ""),
        }
    elif entity == "scenario":
        doc = {
            **common,
            "name": payload.get("name", ""),
            "difficulty": payload.get("difficulty", ""),
            "channels": payload.get("channels", ""),
            "description": payload.get("description", ""),
            "updated_at": payload.get("updated_at", ""),
        }
    elif entity == "saved_report":
        content = payload.get("content_json", {})
        if isinstance(content, str):
            try:
                content = json.loads(content)
            except Exception:
                pass
        doc = {
            **common,
            "title": payload.get("title", ""),
            "created_by": payload.get("created_by", ""),
            "created_at": payload.get("created_at", ""),
            "quiz_count": int(payload.get("quiz_count", 0) or 0),
            "fault_log_count": int(payload.get("fault_log_count", 0) or 0),
            "content_json": content,
        }
    elif entity == "quiz_result":
        doc = {
            **common,
            "student_name": payload.get("student_name", ""),
            "score": int(payload.get("score", 0) or 0),
            "total": int(payload.get("total", 0) or 0),
            "created_at": payload.get("created_at", ""),
        }
    else:  # fault_log
        doc = {
            **common,
            "device_code": payload.get("device_code", ""),
            "channel": int(payload.get("channel", 0) or 0),
            "state": bool(payload.get("state")),
            "action": payload.get("action", ""),
            "actor": payload.get("actor", ""),
            "created_at": payload.get("created_at", ""),
        }

    batch.set(ref, doc, merge=True)


@app.route("/api/sync/push", methods=["POST"])
def sync_push():
    if not authorized():
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    station_id = str(data.get("station_id", "UNKNOWN"))[:100]
    events = data.get("events", [])
    if not isinstance(events, list):
        events = []
    accepted = []

    # Station heartbeat.
    col("stations").document(safe_doc_id(station_id)).set({
        "station_id": station_id,
        "last_seen": now_text(),
    }, merge=True)

    for ev in events:
        event_id = str(ev.get("event_id", "")).strip()
        if not event_id:
            continue

        event_ref = col("sync_events").document(safe_doc_id(event_id))
        if event_ref.get().exists:
            # Idempotent retry: event already received.
            accepted.append(event_id)
            continue

        payload = ev.get("payload", {}) or {}
        if not isinstance(payload, dict):
            payload = {"value": payload}
        entity = str(ev.get("entity_type", ""))
        local_id = str(ev.get("entity_id", ""))
        event_type = str(ev.get("event_type", ""))

        batch = fdb().batch()
        batch.create(event_ref, {
            "event_id": event_id,
            "station_id": station_id,
            "event_type": event_type,
            "entity_type": entity,
            "entity_id": local_id,
            "payload": payload,
            "created_at": ev.get("created_at", ""),
            "received_at": now_text(),
        })
        _upsert_cloud_entity(batch, entity, station_id, local_id, payload, event_type)

        try:
            batch.commit()
            accepted.append(event_id)
        except AlreadyExists:
            # Race/retry: another request stored this event first.
            accepted.append(event_id)

    return jsonify({
        "ok": True,
        "accepted_event_ids": accepted,
        "received": len(accepted),
    })


# =========================================================
# OPTIONAL PUBLIC DASHBOARD
# =========================================================
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
          <p>Cloud API đang hoạt động với <b>Firebase Firestore</b>.</p>
          <p>Dùng <code>/api/health</code> để kiểm tra trạng thái dịch vụ.</p>
          <p>Dữ liệu chi tiết có thể xem trực tiếp trong Firebase Console → Firestore Database.</p>
        </div>
        """)

    stations = all_docs("stations")
    stations.sort(key=lambda x: str(x.get("last_seen", "")), reverse=True)
    collections = {
        "events": "sync_events",
        "users": "auth_users",
        "classes": "classes_cloud",
        "students": "students_cloud",
        "questions": "question_bank",
        "saved_reports": "saved_reports_cloud",
        "quiz": "quiz_results_cloud",
        "faults": "fault_logs_cloud",
    }
    counts = {key: len(all_docs(name)) for key, name in collections.items()}
    recent = all_docs("sync_events")
    recent.sort(key=lambda x: str(x.get("received_at", "")), reverse=True)
    recent = recent[:30]

    return render_template_string("""
    <!doctype html><meta charset="utf-8">
    <style>
    body{font-family:Segoe UI,Arial;background:#f4f6f8;margin:0;color:#1f2937}
    .wrap{max-width:1100px;margin:30px auto}.card{background:#fff;border-radius:12px;padding:18px;margin-bottom:16px}
    .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.n{font-size:30px;font-weight:700;color:#2563eb}
    table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid #e5e7eb;text-align:left}
    </style>
    <div class="wrap">
      <h1>OTO Training Cloud · Firestore</h1>
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


# Initialize Firebase/Firestore and seed required data at process start.
init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"Cloud server: http://127.0.0.1:{port}")
    print("Database backend: Firebase Firestore")
    if not IS_RENDER:
        print("Local demo account: admin / admin123")
        print("Local demo API token: demo-secret-token")
    app.run(host="0.0.0.0", port=port, debug=not IS_RENDER)
