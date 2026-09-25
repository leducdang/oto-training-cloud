# DEPLOY OTO TRAINING CLOUD LÊN RENDER

Bản này đã được chuẩn hóa để deploy **`cloud_server.py`** lên Render. Phần Desktop (`desktop.py`, `app.py`, `hardware_gateway.py`) vẫn chạy trên máy Windows và **không dùng làm Render Start Command**.

## 1. Các file Render đã bổ sung

- `render.yaml`: Blueprint cấu hình Web Service.
- `requirements-render.txt`: chỉ chứa dependency cần cho Cloud, tránh cài PyWebView/PyInstaller/Serial lên Linux server.
- `.python-version`: khóa Python 3.12.
- `.gitignore`: không đưa database runtime, log, report và `.env` lên Git.
- `.env.example`: danh sách biến môi trường mẫu, không chứa secret thật.
- `Procfile`: lệnh khởi động Gunicorn dự phòng.

## 2. Cách deploy dễ nhất: Render Blueprint

1. Giải nén project và đưa **các file bên trong thư mục project** lên một GitHub repository, sao cho `render.yaml` nằm ngay ở root repository.
2. Vào **Render Dashboard → New → Blueprint**.
3. Chọn repository. Render sẽ tự đọc `render.yaml`.
4. Khi Render hỏi secret, nhập:
   - `CLOUD_API_TOKEN`: chuỗi bí mật dài, khuyến nghị >= 32 ký tự.
   - `INITIAL_ADMIN_PASSWORD`: mật khẩu admin ban đầu, tối thiểu 8 ký tự.
5. Chọn Deploy Blueprint.
6. Khi service báo Live, mở:
   - `https://<ten-service>.onrender.com/api/health`
   - Kết quả đúng phải có `"ok": true` và `"database": "ok"`.

Tài khoản Cloud ban đầu:

- Username: `admin`
- Password: giá trị `INITIAL_ADMIN_PASSWORD` bạn đã nhập trên Render.

## 3. Cấu hình máy Desktop kết nối Cloud

Mở `config.json` của Desktop và sửa:

```json
{
  "cloud_url": "https://<ten-service>.onrender.com",
  "api_token": "DUNG_CHUOI_CLOUD_API_TOKEN_DA_NHAP_TREN_RENDER"
}
```

Không thêm dấu `/` ở cuối `cloud_url`.

## 4. Nếu tạo Web Service thủ công thay vì Blueprint

- Language: `Python 3`
- Build Command: `pip install --upgrade pip && pip install -r requirements-render.txt`
- Start Command: `gunicorn cloud_server:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 60`
- Health Check Path: `/api/health`
- Environment Variables:
  - `CLOUD_API_TOKEN` = token bí mật >= 16 ký tự
  - `INITIAL_ADMIN_PASSWORD` = mật khẩu admin >= 8 ký tự
  - `INITIAL_ADMIN_USERNAME` = `admin`
  - `CLOUD_SESSION_HOURS` = `12`
  - `CLOUD_PUBLIC_DASHBOARD` = `false`

## 5. Lưu ý rất quan trọng về SQLite trên Render Free

Cloud hiện dùng SQLite (`cloud.db`). Render Free không có Persistent Disk, vì vậy dữ liệu ghi vào filesystem có thể mất khi service restart hoặc redeploy. Cấu hình này phù hợp để **test**, không phù hợp cho bản thương mại/production.

Khi chuyển sang Render trả phí, có thể:

1. Tạo Persistent Disk mount tại `/var/data`.
2. Thêm Environment Variable `CLOUD_DATA_DIR=/var/data`.

Hoặc tốt hơn cho bản thương mại: chuyển Cloud DB sang PostgreSQL.

## 6. Các thay đổi bảo mật đã thực hiện

- Khi chạy trên Render, server không còn cho phép dùng mặc định `demo-secret-token` hoặc `admin123`. Nếu thiếu secret, quá trình khởi động sẽ dừng và báo rõ biến nào chưa cấu hình.
- API key được so sánh bằng hàm constant-time.
- Bearer login token được lưu dạng SHA-256 trong DB thay vì giữ raw token trong RAM.
- Token có thời hạn, mặc định 12 giờ.
- Root dashboard public không hiển thị station/event/user count trên Render.
- `/api/health` có truy vấn DB nhẹ để kiểm tra cả Web Service và database.
- Gunicorn cố định 1 worker để phù hợp với SQLite; dùng 4 threads để xử lý nhiều request nhẹ.

## 7. Local demo vẫn giữ nguyên

Khi chạy local và không set environment variable:

- Cloud: `http://127.0.0.1:8000`
- Admin: `admin / admin123`
- API token: `demo-secret-token`

Chạy:

```powershell
python cloud_server.py
```

Các giá trị demo trên chỉ dùng ở máy local.
