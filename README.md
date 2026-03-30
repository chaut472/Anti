# CyberShield IDS/IPS System

Hệ thống Phát hiện và Ngăn chặn Xâm nhập mạng (IDS/IPS) được xây dựng bằng Python và Flask.

## 🚀 Khởi động hệ thống

```bash
# Cài đặt thư viện
pip install -r requirements.txt

# Chạy ứng dụng
python app.py
```

Mở trình duyệt tại: http://localhost:5000

## 📁 Cấu trúc dự án

```
Anti/
├── app.py                  # Flask application chính
├── requirements.txt        # Dependencies
├── core/
│   ├── ids_engine.py       # IDS/IPS Engine (phát hiện + mô phỏng)
│   └── data_store.py       # Quản lý dữ liệu
├── templates/
│   ├── base.html           # Layout template
│   ├── dashboard.html      # Trang chính
│   ├── monitor.html        # Giám sát lưu lượng mạng
│   ├── threats.html        # Phân tích mối đe dọa
│   ├── logs.html           # Nhật ký sự kiện
│   ├── blocked.html        # IP bị chặn
│   ├── rules.html          # Quy tắc phát hiện
│   └── about.html          # Về hệ thống
└── static/
    ├── css/main.css        # Stylesheet chính
    └── js/main.js          # JavaScript chính
```

## 🔍 Các tính năng

- **Dashboard**: Tổng quan thời gian thực (gói tin, cảnh báo, IP bị chặn)
- **Giám sát mạng**: Phân tích lưu lượng, giao thức, băng thông live
- **Phân tích mối đe dọa**: Phân loại tấn công, top IP tấn công
- **Nhật ký sự kiện**: Lọc và tìm kiếm toàn bộ cảnh báo
- **Quản lý IP**: Chặn/bỏ chặn IP thủ công và tự động
- **Quy tắc phát hiện**: Bật/tắt quy tắc IDS/IPS

## 🛡️ Các loại tấn công phát hiện

- SYN Flood, ICMP Flood, HTTP Flood (DoS/DDoS)
- SQL Injection, XSS Attack (Web Attack)  
- Port Scan, Nmap OS Detection (Reconnaissance)
- SSH Brute Force, FTP Brute Force (Brute Force)