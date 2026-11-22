# Hướng Dẫn Sử Dụng & Vận Hành Zimbra Outbound Spam Monitor (`v1.3.2`)

Tài liệu này cung cấp cẩm nang chi tiết từ cài đặt, cấu hình, vận hành hằng ngày đến quy trình xử lý sự cố (SOP) dành cho Quản trị viên hệ thống (Sysadmin) vận hành máy chủ mail **Zimbra Collaboration Suite (ZCS 8 / 9 / 10)** trên Linux (RHEL, CentOS, Rocky Linux, AlmaLinux, Ubuntu, Debian).

---

## Mục Lục

1. [Tổng Quan & Cam Kết An Toàn Tuyệt Đối](#1-tổng-quan--cam-kết-an-toàn-tuyệt-đối)
2. [Cài Đặt & Triển Khai Nhanh](#2-cài-đặt--triển-khai-nhanh)
3. [Cấu Trúc Thư Mục & File Cấu Hình](#3-cấu-trúc-thư-mục--file-cấu-hình)
4. [Bảng Điều Khiển TUI & Lệnh CLI](#4-bảng-điều-khiển-tui--lệnh-cli)
5. [11 Cơ Chế Phát Hiện Spam & Chống Khóa Nhầm](#5-11-cơ-chế-phát-hiện-spam--chống-khóa-nhầm)
6. [Cơ Chế Điểm Rủi Ro Tổng Hợp (Composite Risk Score)](#6-cơ-chế-điểm-rủi-ro-tổng-hợp-composite-risk-score)
7. [Quy Trình Chuẩn Xử Lý Sự Cố (SOP)](#7-quy-trình-chuẩn-xử-lý-sự-cố-sop)
8. [Gỡ Cài Đặt (Uninstall)](#8-gỡ-cài-đặt-uninstall)

---

## 1. Tổng Quan & Cam Kết An Toàn Tuyệt Đối

`zimbra-spam-monitor` là giải pháp giám sát thư rác chiều đi (outbound spam), cảnh báo đa kênh (Telegram, Email, Webhook, JSONL) và tự động cô lập tài khoản bị lộ lọt thông tin đăng nhập dành riêng cho Zimbra.

### Cam kết an toàn cốt lõi:
- **Zero Mail Server / OS Mutation (Tuyệt đối không can thiệp cấu hình hệ thống)**:
  - Ứng dụng **chỉ đọc (read-only)** log và trạng thái queue của mail server.
  - Tuyệt đối **không bao giờ** chạy các lệnh thay đổi cấu hình Postfix (`postconf -e`), Zimbra (`zmlocalconfig -e`, `zmprov mcf/ms/mc/md`), không tự khởi động lại dịch vụ (`zmcontrol`, `postfix reload`, `systemctl`), không tác động tới tường lửa (`iptables`, `nftables`, `firewalld`, `fail2ban`) hay kernel (`sysctl`).
- **Phạm vi xử lý sự cố duy nhất**:
  - Khi phát hiện một tài khoản đạt ngưỡng **CRITICAL** (chắc chắn bị botnet spam/compromised), công cụ chỉ thực hiện đúng 2 thao tác an toàn:
    1. Khóa tài khoản duy nhất đó: `zmprov ma <account> zimbraAccountStatus locked`
    2. Xóa sạch cache xác thực của riêng tài khoản đó: `zmprov fc account <account>` (hủy ngay lập tức token Webmail/SOAP/ActiveSync của kẻ tấn công mà không làm gián đoạn bất kỳ người dùng nào khác).
- **Tiêu thụ tài nguyên siêu thấp**:
  - Không chạy daemon chạy nền tốn RAM, tự hạ mức ưu tiên xử lý (`nice -n 19`, `ionice -c 3`).
  - Lọc log thời gian thực với bộ đệm `mktime()` cache theo từng giây và pre-filter bằng C-grep, chiếm dưới **25MB RAM** và hoàn tất chu kỳ quét trong **1-2 giây**.

---

## 2. Cài Đặt & Triển Khai Nhanh

Ứng dụng được đóng gói sẵn dưới dạng `.rpm` và `.deb` tại trang GitHub Releases:
👉 https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/tag/v1.3.2

### A. Dành cho RHEL / CentOS / Rocky Linux / AlmaLinux (`.rpm`)
Chạy với quyền `root` trên máy chủ Zimbra:
```bash
wget -O zimbra-spam-monitor-1.3.2-1.noarch.rpm https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/download/v1.3.2/zimbra-spam-monitor-1.3.2-1.noarch.rpm
rpm -Uvh zimbra-spam-monitor-1.3.2-1.noarch.rpm
```
*(Hoặc dùng `dnf localinstall -y zimbra-spam-monitor-1.3.2-1.noarch.rpm`)*

### B. Dành cho Ubuntu / Debian (`.deb`)
Chạy với quyền `root` trên máy chủ Zimbra:
```bash
wget -O zimbra-spam-monitor_1.3.2-1_all.deb https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/download/v1.3.2/zimbra-spam-monitor_1.3.2-1_all.deb
apt install -y ./zimbra-spam-monitor_1.3.2-1_all.deb
```
*(Hoặc dùng `dpkg -i zimbra-spam-monitor_1.3.2-1_all.deb && apt-get install -f -y` để tự cài thêm `gawk` nếu máy chưa có)*

### Cơ chế tự động kích hoạt sau khi cài đặt:
- File nhị phân điều khiển chính: `/usr/bin/zimbra-spam-monitor`
- File lịch quét định kỳ tự động tạo tại: `/etc/cron.d/zimbra-spam-monitor` (mặc định quét mỗi 5 phút một lần).
- File xoay vòng nhật ký tự động tạo tại: `/etc/logrotate.d/zimbra-spam-monitor`.

---

## 3. Cấu Trúc Thư Mục & File Cấu Hình

Toàn bộ dữ liệu của ứng dụng được đặt gọn gàng trong các đường dẫn chuẩn Linux:

| Đường dẫn | Mục đích |
| :--- | :--- |
| `/usr/bin/zimbra-spam-monitor` | File thực thi chính (Bash script độc lập). |
| `/etc/zimbra-spam-monitor/config.conf` | File cấu hình tham số hoạt động, ngưỡng cảnh báo, thông tin bot. |
| `/etc/zimbra-spam-monitor/whitelist.conf` | Danh sách tài khoản miễn trừ (Bypass) hoặc hạn mức riêng. |
| `/var/lib/zimbra-spam-monitor/` | Thư mục trạng thái (cache LDAP domain, IP cache, outbox retry, locked accounts). |
| `/var/log/zimbra-spam-monitor.log` | Nhật ký hoạt động chi tiết dạng text thông thường. |
| `/var/log/zimbra-spam-monitor-events.jsonl` | Nhật ký sự kiện dạng JSON Lines có cấu trúc (dành cho SIEM / Wazuh / ELK). |

### Hướng dẫn cấu hình `whitelist.conf`:
File `/etc/zimbra-spam-monitor/whitelist.conf` hỗ trợ 2 cơ chế linh hoạt:
1. **Miễn trừ hoàn toàn (Full Bypass)**: Bỏ qua kiểm tra hạn mức cho tài khoản nội bộ đặc biệt hoặc toàn bộ domain:
   ```text
   marketing-newsletter@company.com
   @trusted-partner.com
   ```
2. **Hạn mức riêng cho từng tài khoản (Per-Account Custom Limits)**:
   Cú pháp: `<email> <ngưỡng_cảnh_báo> <ngưỡng_khóa>`
   Ví dụ phòng kế toán hoặc phòng nhân sự gửi bảng lương, thông báo định kỳ:
   ```text
   ketoan@company.com 500 1000
   hr-notify@company.com 300 600
   ```
   *Lưu ý: Kể cả khi có hạn mức riêng, nếu tài khoản bị kẻ xấu chèn mã độc giả mạo người gửi (Sender Spoofing) hoặc phát hiện mã độc Amavis, hệ thống vẫn sẽ kích hoạt bảo vệ!*

---

## 4. Bảng Điều Khiển TUI & Lệnh CLI

### 4.1 Bảng Điều Khiển Trực Quan (TUI)
Chạy lệnh sau trên terminal (SSH):
```bash
zimbra-spam-monitor
```
Hệ thống tự động mở giao diện điều khiển bằng phím mũi tên (hỗ trợ `whiptail` hoặc `dialog`). Nếu chạy trong môi trường không có terminal giả lập, có thể dùng cờ `--text-menu` để dùng menu số đơn giản (`1..6`).

```text
==============================================================================
 ZIMBRA SPAM MONITOR v1.3.2
------------------------------------------------------------------------------
 Service: ON | Check: Every 5 mins | Auto-Lock: ON | TG: ON | Mail: ON
------------------------------------------------------------------------------
  [1 ] Live Status & Queue    (Xem trạng thái trực tiếp & danh sách tài khoản bị khóa)
  [2 ] Alerts & Test          (Cấu hình Telegram / Email / Webhook / Gửi mail test)
  [3 ] Spam Limits & Schedule (Cấu hình ngưỡng 5m, 1h, chu kỳ cron, Risk Score)
  [4 ] Unlock & Auto-Lock     (Mở khóa tài khoản, bật/tắt Auto-Lock, Auto-Hold Queue)
  [5 ] Whitelist & Limits     (Quản lý tài khoản Whitelist & hạn mức riêng)
  [6 ] Logs, RBL & Audit      (Bật/tắt giám sát, xem log, check RBL & Zimbra Audit)
  [0 ] Exit                   (Thoát)
==============================================================================
```

### Các mục tinh chỉnh nổi bật trong Menu `[3]` (`Spam Limits & Schedule`):
- `[4] Outbound Limits`: Cấu hình số lượng thư và người nhận trong khung 5 phút (`WARN_RECIPIENTS`, `CRIT_RECIPIENTS`).
- `[7] Hourly Limit (1h)`: Cấu hình nhanh ngưỡng tích lũy theo giờ (`WARN_HOURLY_MESSAGES`, `CRIT_HOURLY_MESSAGES`).
- `[8] Risk Score Engine`: Bật/Tắt chế độ chấm điểm rủi ro tổng hợp thông minh (`ON`/`OFF`).

---

### 4.2 Các Lệnh Dòng Lệnh Trực Tiếp (CLI)

Sysadmin có thể thực hiện mọi thao tác nhanh bằng một dòng lệnh CLI mà không cần mở menu:

| Lệnh CLI | Công dụng |
| :--- | :--- |
| `zimbra-spam-monitor --status` | Xem bảng thống kê lưu lượng 5 phút vừa qua, trạng thái queue và danh sách tài khoản đang bị khóa. |
| `zimbra-spam-monitor --test` | Gửi cảnh báo kiểm tra thử nghiệm tới các kênh đã bật (Telegram, Email, Webhook). |
| `zimbra-spam-monitor --unlock <user>` | Mở khóa tài khoản, hủy cooldown và **xóa sạch lịch sử 1h/24h** để người dùng gửi thư bình thường ngay lập tức. |
| `zimbra-spam-monitor --whitelist-add <user>` | Thêm tài khoản/domain vào danh sách miễn trừ (tự động xóa trùng lặp). |
| `zimbra-spam-monitor --whitelist-add <user> 500 1000` | Gán hạn mức gửi riêng (Cảnh báo: 500 / Khóa: 1000) cho tài khoản. |
| `zimbra-spam-monitor --check-rbl` | Kiểm tra IP mail server có bị rơi vào các danh sách đen thế giới (DNSBL Spamhaus, Spamcop, Barracuda...) hay không. |
| `zimbra-spam-monitor --audit` | Khảo sát an ninh Postfix & Zimbra (100% read-only): kiểm tra SPF, DMARC, Open Relay, Sender Login Mismatch... |

---

## 5. 11 Cơ Chế Phát Hiện Spam & Chống Khóa Nhầm

`zimbra-spam-monitor` tổng hợp 11 tín hiệu nhận diện hành vi gửi thư bất thường:

| # | Tín hiệu | Cách tính toán | Ngưỡng `WARNING` | Ngưỡng `CRITICAL` (Khóa) |
| :-: | :--- | :--- | :--- | :--- |
| **1** | **Messages Sent** | Số Queue-ID gốc gửi đi trong 5 phút | `>= 60` thư | `>= 150` thư |
| **2** | **Total Recipients** | Tổng số người nhận (deduped theo thư) | `>= 100` người nhận | `>= 200` người nhận *(yêu cầu `Thư >= 10`)* |
| **3** | **Unique Recipients** | Số người nhận duy nhất sang `>= 5` domain khác | `>= 80` người nhận | `>= 160` người nhận *(yêu cầu `Thư >= 10`)* |
| **4** | **Failed Rate (%)** | Tỷ lệ thư bị từ chối / hoãn lại (Deferred + Bounced) | `>= 30%` *(tối thiểu 20 người nhận)* | `>= 50%` *(tối thiểu 40 người nhận)* |
| **5** | **Distinct Source /24s** | Số dải mạng IP /24 gửi thư (kể cả Webmail từ `mailbox.log`) | `>= 3` dải mạng | `>= 5` dải mạng *(tối thiểu 20 thư)* |
| **6** | **Sender Spoofing** | Xác thực tài khoản A nhưng Header From là domain ngoài | `>= 3` thư | `>= 10` thư |
| **7** | **Amavis SPAM / RBL** | Amavis gắn cờ `SPAMMY/INFECTED` (`Hits >= 6.0`) | `>= 3` tín hiệu | `>= 10` tín hiệu |
| **8** | **Account Live Queue** | Số thư đang tồn đọng trong Active/Deferred queue | `>= 40` thư | `>= 100` thư |
| **9** | **Low-and-Slow (1h/24h)** | Thống kê tích lũy dàn trải theo giờ | `300/1h` hoặc `1500/24h` | `600/1h` thư *(24h chỉ cảnh báo WARN)* |
| **10** | **Brute-Force / Auth** | Dò quét mật khẩu trong `audit.log` và Postfix SASL | Cảnh báo gom dải IP | Không bao giờ khóa nhầm nạn nhân |
| **11** | **Composite Risk Score** | Điểm rủi ro đa tiêu chí kết hợp (0 - 100) | `>= 60` điểm | `>= 85` điểm |

### Các Lớp Bảo Vệ Chống Khóa Nhầm Tuyệt Đối:
- **Gửi thông báo nội bộ / BCC hợp lệ**: Người dùng gửi 1 email cho 200 đối tác cùng lúc (`Msgs = 1 < 10`) — kể cả khi đường truyền/DNS chập chờn gây `deferred` — sẽ chỉ bị cảnh báo `WARNING`, **không bao giờ bị khóa tài khoản**.
- **Miễn nhiễm tấn công ép khóa từ bên ngoài (Inbound Spoof DoS)**: Tách biệt hoàn toàn luồng thư chiều đến từ Internet kể cả khi đi qua Amavis (`127.0.0.1:10025`) và `postfix/lmtp[`, đảm bảo kẻ tấn công bên ngoài giả mạo `From` nội bộ không bao giờ có thể ép khóa tài khoản người dùng.
- **Cầu chì giới hạn khóa (`MAX_LOCKS_PER_CYCLE=5`) & Bảo vệ tài khoản hệ thống**: Nếu có sự cố mạng/DNS diện rộng làm nhiều tài khoản vượt ngưỡng cùng lúc, hệ thống chỉ khóa tối đa 5 tài khoản/chu kỳ rồi chuyển sang chế độ cảnh báo; đồng thời luôn bảo vệ các tài khoản hệ thống Zimbra (`spam.*`, `ham.*`, `virus-quarantine.*`, `galsync.*`) và danh sách `PROTECTED_ACCOUNTS` tùy chọn.
- **Chuyển tiếp thư tự động (Auto-Forward)**: Khi người dùng chuyển tiếp mail ra Gmail và Gmail phản hồi mã lỗi `5.7.1` (do nội dung gốc là spam), hệ thống nhận diện xuất xứ từ Webmail/Local và chỉ gửi `WARNING`, không khóa tài khoản.
- **Mạng 4G/5G xoay IP liên tục**: Khi người dùng dùng 4G đổi IP liên tục trong cùng dải `/24` của nhà mạng, hệ thống gom chung thành 1 dải mạng duy nhất.
- **Thư gửi lại (Deferred Retries)**: Postfix thử gửi lại thư cũ từ 30 phút trước sẽ không bị cộng dồn thành spam mới của chu kỳ 5 phút hiện tại.
- **Giao thư nội bộ sau Amavis (`postfix/lmtp[`)**: Kiểm soát luồng giao thư nội bộ qua LMTP port 7025 để phát hiện virus lây lan nội bộ, đồng thời bỏ qua 100% thư nhận từ ngoài Internet vào.

---

## 6. Cơ Chế Điểm Rủi Ro Tổng Hợp (Composite Risk Score)

Kẻ tấn công tinh vi thường cố tình gửi thư dưới ngưỡng cảnh báo đơn lẻ (ví dụ: mỗi ngưỡng chỉ vi phạm 40-50%). Để ngăn chặn hành vi này, `zimbra-spam-monitor` áp dụng thuật toán chấm điểm rủi ro:

- **Thang điểm**: `0` đến `100`.
- **Ngưỡng hành động**:
  - `Risk Score >= 60`: Gửi cảnh báo **WARNING** (yêu cầu ít nhất 2 tín hiệu bất thường).
  - `Risk Score >= 85`: Kích hoạt **CRITICAL & Tự Động Khóa** (yêu cầu ít nhất 3 tín hiệu bất thường và có ít nhất 1 tín hiệu chất lượng cao như Botnet IP, Spoofing hoặc Amavis Spammy).

### Bảng trọng số tính điểm:
- Tỷ lệ gửi thất bại (`Failed Rate >= 30%`): +16 điểm.
- Giả mạo người gửi (`Sender Spoofing >= 2`): +16 điểm.
- Amavis gắn cờ thư rác (`Amavis Hits >= 6.0`): +16 điểm.
- Lưu lượng gửi (`Messages >= 40`): +12 điểm.
- Phân tán IP (`Distinct /24 IPs >= 2`): +13 điểm.
- Hàng đợi tồn đọng (`Queue >= 30`): +13 điểm.
- Lịch sử gửi chậm trong 1 giờ (`Hourly Count >= 200`): +14 điểm.

---

## 7. Quy Trình Chuẩn Xử Lý Sự Cố (SOP)

### Kịch bản 1: Nhận được thông báo Telegram/Email có tài khoản bị KHÓA (`CRITICAL`)

Khi nhận cảnh báo `[CRITICAL] Compomised Account Locked: user@domain.com`:

1. **Kiểm tra trạng thái hệ thống**:
   ```bash
   zimbra-spam-monitor --status
   ```
   Xem chi tiết số lượng thư, dải IP kết nối và lý do tài khoản bị khóa trong bảng hiển thị.
2. **Xử lý tài khoản người dùng**:
   - Yêu cầu người dùng quét virus/malware trên thiết bị cá nhân.
   - Quản trị viên đổi mật khẩu mới cho tài khoản (có thể thực hiện trên Zimbra Admin Console hoặc lệnh `zmprov sp user@domain.com 'MatKhauMoi#123'`).
3. **Mở khóa tài khoản an toàn**:
   ```bash
   zimbra-spam-monitor --unlock user@domain.com
   ```
   *Lệnh này sẽ tự động: chuyển trạng thái tài khoản về `active`, xóa cache đăng nhập cũ, xóa cooldown cảnh báo, và dọn sạch lịch sử 1h/24h của tài khoản đó để người dùng có thể gửi mail công việc bình thường ngay lập tức mà không bị khóa lại.*

---

### Kịch bản 2: Phòng ban cần gửi thông báo hoặc chiến dịch hợp lệ số lượng lớn

Nếu phòng Marketing hoặc Nhân sự cần gửi 800 thư thông báo cho khách hàng:
1. Chạy lệnh cấp hạn mức riêng tạm thời:
   ```bash
   zimbra-spam-monitor --whitelist-add marketing@company.com 500 1000
   ```
2. Sau khi chiến dịch hoàn tất, có thể xóa hoặc hạ hạn mức qua giao diện menu:
   ```bash
   zimbra-spam-monitor -> Chọn [5] Whitelist & Limits -> [3] Remove Whitelist Entry
   ```

---

### Kịch bản 3: Tích hợp cảnh báo Telegram & Webhook (Teams / Slack / Zalo)

1. Mở menu cấu hình:
   ```bash
   zimbra-spam-monitor -> Chọn [2] Alerts & Test
   ```
2. Điền `Telegram Bot Token` và `Telegram Chat ID`.
3. Bật `Webhook Alerting` và nhập URL Webhook (hỗ trợ định dạng JSON phổ biến của Slack, Microsoft Teams, hoặc các gateway tin nhắn nội bộ).
4. Chọn `[3] Send Test Alert` để kiểm tra kết nối ngay trên màn hình.

---

## 8. Gỡ Cài Đặt (Uninstall)

Khi cần gỡ cài đặt hoàn toàn khỏi máy chủ:

- **Trên RHEL / CentOS / Rocky Linux / AlmaLinux**:
  ```bash
  rpm -e zimbra-spam-monitor
  ```
- **Trên Ubuntu / Debian**:
  ```bash
  apt purge -y zimbra-spam-monitor
  ```

Quá trình gỡ cài đặt sẽ tự động dọn sạch file cronjob tại `/etc/cron.d/` và logrotate, đảm bảo không để lại bất kỳ tiến trình nào chạy trên máy chủ.
