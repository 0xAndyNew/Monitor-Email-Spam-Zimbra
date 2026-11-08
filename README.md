# Zimbra Outbound Spam Monitor (`zimbra-spam-monitor`)

Hệ thống giám sát tự động phát hiện tài khoản email **Zimbra Collaboration Suite (ZCS)** bị chiếm quyền (hacked) đang phát tán spam ra ngoài, gửi cảnh báo tức thời qua **Telegram** và **Email**, đồng thời hỗ trợ **tự động khóa tài khoản (`locked`)** khi vượt ngưỡng nguy hiểm.

Tích hợp **Giao diện Bảng Điều Khiển Chọn Mục (TUI Hộp thoại dùng phím mũi tên $\uparrow/\downarrow$ & Menu chọn số)** giúp cài đặt và tinh chỉnh mọi thông số ngay trên màn hình SSH.

---

## 1. Cài đặt nhanh từ GitHub Releases (`.rpm` & `.deb`)

Trang tải bản phát hành (Releases): https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/tag/v1.0.0

### A. Trên CentOS / RHEL / Rocky Linux / AlmaLinux (Gói `.rpm`)
Chạy lệnh sau với quyền `root` trên server Zimbra:
```bash
wget -O zimbra-spam-monitor-1.0.0-1.noarch.rpm https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/download/v1.0.0/zimbra-spam-monitor-1.0.0-1.noarch.rpm
rpm -ivh zimbra-spam-monitor-1.0.0-1.noarch.rpm
```
*(Hoặc dùng `yum localinstall -y zimbra-spam-monitor-1.0.0-1.noarch.rpm`)*

### B. Trên Ubuntu / Debian (Gói `.deb`)
Chạy lệnh sau với quyền `root` trên server Zimbra:
```bash
wget -O zimbra-spam-monitor_1.0.0-1_all.deb https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/download/v1.0.0/zimbra-spam-monitor_1.0.0-1_all.deb
dpkg -i zimbra-spam-monitor_1.0.0-1_all.deb
```

---

## 2. Hướng dẫn Sử dụng Giao diện Bảng Điều Khiển

Sau khi cài đặt xong gói `.rpm` hoặc `.deb`, anh chỉ cần gõ lệnh:
```bash
zimbra-spam-monitor
```
*(Nếu server có sẵn `whiptail`/`dialog`, hệ thống hiển thị **hộp thoại đồ họa màu xanh** dùng phím **Mũi tên Lên/Xuống + Enter** để chọn; hoặc chạy `zimbra-spam-monitor --text-menu` để chọn bằng phím số `1..8`).*

### Giao diện Menu chính:
```text
==============================================================================
 BẢNG ĐIỀU KHIỂN ZIMBRA SPAM MONITOR v1.1.0
------------------------------------------------------------------------------
 Trạng thái: [ĐANG BẬT] | Chu kỳ: [5 phút/lần] | Khóa tự động: [BẬT]
------------------------------------------------------------------------------
  [1 ] Xem Bảng Trạng Thái & Top Tài Khoản Gửi Mail hiện tại
  [2 ] Cấu hình Cảnh báo & Test (TG:BẬT | Mail:admin@domain.com)
  [3 ] Chỉnh sửa Ngưỡng Cảnh Báo Spam (10p: 80/200 | 1h: 300/600)
  [4 ] Cài đặt Tự Động Khóa & Mở Khóa Tài Khoản (Auto-Lock: BẬT)
  [5 ] Quản lý Danh Sách Miễn Trừ - Whitelist (Thêm / Chọn xóa)
  [6 ] Thay đổi Chu Kỳ Quét Tự Động Cron (5 phút/lần)
  [7 ] Bật / Tắt toàn bộ hệ thống Giám Sát (Hiện tại: ĐANG BẬT)
  [8 ] Xem Nhật Ký Hoạt Động gần nhất (/var/log/zimbra-spam-monitor.log)
  [0 ] Thoát
==============================================================================
```

### Chi tiết các Menu chức năng:

#### 1. Menu `[2]` — Cấu hình Kênh Cảnh Báo & Gửi Test (Gộp chung Telegram + Email + Test)
Khi chọn mục `[2]`, hệ thống mở ra Menu con gồm:
- **`[1] Cấu hình Cảnh báo Telegram`**:
  - Bật / Tắt cảnh báo Telegram.
  - Nhập `TELEGRAM_BOT_TOKEN` (lấy từ `@BotFather`).
  - Nhập `TELEGRAM_CHAT_ID` (ID cá nhân hoặc nhóm nhận cảnh báo).
- **`[2] Cấu hình Cảnh báo Email & SMTP`**:
  - Bật / Tắt cảnh báo Email.
  - Chọn phương thức gửi:
    - `auto`: Tự động dùng Postfix nội bộ của Zimbra, nếu hàng đợi nghẽn và có SMTP ngoài thì tự chuyển sang SMTP ngoài.
    - `local`: Chỉ dùng Postfix nội bộ của Zimbra (không cần nhập tài khoản SMTP).
    - `smtp`: Chỉ dùng máy chủ SMTP bên ngoài.
  - Chọn địa chỉ nhận cảnh báo: Để `auto` (tự động lấy Email Admin mặc định của hệ thống Zimbra) hoặc nhập email tùy chỉnh.
- **`[3] Gửi thử tin nhắn Test Cảnh Báo (Telegram & Email)`**:
  - Kiểm tra kết nối gửi ngay lập tức 1 bản tin thử nghiệm về cả Telegram và Email.

#### 2. Menu `[3]` — Chỉnh sửa Ngưỡng Cảnh Báo Spam
Chọn đúng ngưỡng cần điều chỉnh mà không phải nhập lại các thông số khác:
- Khoảng thời gian quét ngắn (Mặc định: `10 phút`).
- Ngưỡng **WARNING** & **CRITICAL** trong 10 phút (Mặc định: `80` / `200` email).
- Ngưỡng **WARNING** & **CRITICAL** trong 1 Giờ - 60 phút (Mặc định: `300` / `600` email).
- Ngưỡng **WARNING** & **CRITICAL** số mail đang kẹt trong Queue của 1 tài khoản (Mặc định: `40` / `100` email).
- Ngưỡng **WARNING** tổng hàng đợi toàn Server (Mặc định: `300` email).
- Thời gian nghỉ chống lặp thông báo Cooldown (Mặc định: `30 phút`).

#### 3. Menu `[4]` — Cài đặt Tự Động Khóa & Mở Khóa Tài Khoản
- Bật / Tắt tự động khóa tài khoản (`zimbraAccountStatus locked`) khi chạm mức **CRITICAL**.
- Bật / Tắt tự động tạm giữ (`hold`) các mail spam đang chờ trong Queue của tài khoản đó.
- **Chọn mở khóa nhanh tài khoản bị khóa tự động**: Hiển thị danh sách các tài khoản vừa bị khóa để bấm chọn mở khóa ngay sau khi đã đổi mật khẩu.

#### 4. Menu `[5]` — Quản lý Danh Sách Miễn Trừ (Whitelist)
- Xem danh sách các tài khoản / tên miền được miễn trừ.
- Thêm địa chỉ email (ví dụ `marketing@congty.com`) hoặc tên miền (`@congty.com`).
- Chọn xóa trực tiếp từ danh sách hiển thị trên màn hình.

#### 5. Menu `[6]` — Thay đổi Chu Kỳ Quét Tự Động (Cronjob)
- Chọn 1 chạm chu kỳ quét: `1 phút/lần`, `2 phút/lần`, `5 phút/lần` (Khuyên dùng), `10 phút/lần`, `15 phút/lần`, `30 phút/lần`, hoặc `Tạm dừng`.

---

## 3. Các lệnh CLI chạy nhanh (Tùy chọn)

Ngoài giao diện chọn `zimbra-spam-monitor`, anh có thể gọi nhanh từ dòng lệnh:
```bash
zimbra-spam-monitor --status                 # Xem bảng thống kê trực tiếp
zimbra-spam-monitor --test                   # Gửi thử cảnh báo Telegram & Email
zimbra-spam-monitor --unlock user@domain.com # Mở khóa nhanh tài khoản
zimbra-spam-monitor --whitelist-add a@b.com  # Thêm nhanh vào Whitelist
```

---

## 4. Gỡ cài đặt hoàn toàn khỏi Server

- **Trên CentOS / RHEL / Rocky Linux:**
  ```bash
  rpm -e zimbra-spam-monitor
  ```
- **Trên Ubuntu / Debian:**
  ```bash
  apt purge -y zimbra-spam-monitor
  ```

---

## 5. Đóng gói lại từ Mã nguồn (Dành cho Developer)
Nếu chỉnh sửa mã nguồn trong thư mục `src/` hoặc `config/`, chạy lệnh sau để đóng gói lại cả 2 file `.rpm` và `.deb`:
```bash
python3 packaging/build_rpm_deb.py
```
