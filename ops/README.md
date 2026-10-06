# ops – hạ tầng cho dự án VPN (1 controller + 2 gateway, Ubuntu 22.04)

Mọi cấu hình server nằm trong repo này và được áp bằng **Ansible**. Không sửa tay trên server.

```
ops/
├── ansible.cfg · requirements.yml · .yamllint · .ansible-lint
├── inventory/            hosts.yml (IP lấy từ biến môi trường) + group_vars/
├── playbooks/            site.yml (áp tất cả) · verify.yml (kiểm tra) · storage.yml (LVM, CHẠY TAY)
├── roles/
│   ├── base              gói cơ bản, chrony, tự cập nhật bảo mật, sysctl hardening
│   ├── ssh_hardening     user admin/deploy, authorized_keys, sshd_config (key-only, cấm root)
│   ├── ufw               default deny incoming; SSH, cổng VPN, node_exporter chỉ cho controller
│   ├── fail2ban          jail sshd + recidive (ban tăng dần), banaction = ufw
│   ├── auditd            rules (identity, sudo, ssh, firewall, modules, delete...)
│   ├── storage           LVM + /etc/fstab (nodev,nosuid,noexec) – opt-in, chạy tay
│   ├── lynis             audit hằng tuần → điểm hardening thành metric
│   ├── node_exporter     metric hệ thống + metric tuỳ biến (fail2ban, reboot, updates, lynis)
│   ├── monitoring_stack  (controller) Docker: Prometheus, Alertmanager→Telegram, Grafana
│   └── egressa           triển khai binary controller/gateway của Egressa + systemd unit
└── scripts/              first-run.sh · deploy.sh · build-artifacts.sh · gen-deploy-key.sh
../.github/workflows/     ops-ci.yml (lint/test) · ops-cd.yml (tự deploy khi merge vào main)
```

## 1. Thiết lập lần đầu (từ máy cá nhân)

1. `pip install ansible-core` rồi `ansible-galaxy collection install -r requirements.yml`.
2. Đưa **public key** của máy bạn vào `inventory/group_vars/all.yml` → `ssh_authorized_keys.isQHung`.
3. `scripts/gen-deploy-key.sh` → sinh key cho CI/CD; dán public key vào `ssh_authorized_keys.deploy`, đặt private key vào GitHub Secret (lệnh in sẵn).
4. Tạo bot Telegram: chat với **@BotFather** → `/newbot` → lấy token; nhắn 1 tin cho bot rồi mở
   `https://api.telegram.org/bot<TOKEN>/getUpdates` để lấy `chat.id`.
5. `export` các biến (bảng bên dưới) rồi chạy `scripts/first-run.sh` (giữ sẵn 1 phiên SSH khác đang mở).
   Role `ssh_hardening` từ chối chạy nếu key còn là `REPLACE_ME` – để tránh tự khoá mình ngoài server.

## 2. GitHub: Secrets và CI/CD

Tạo Environment `production` (Settings → Environments), thêm các secret:

| Secret | Nội dung |
|---|---|
| `DEPLOY_SSH_PRIVATE_KEY` | private key của user `deploy` |
| `SSH_KNOWN_HOSTS` | kết quả `ssh-keyscan` của 3 server (kiểm tra fingerprint trước) |
| `CONTROLLER_IP`, `GATEWAY1_IP`, `GATEWAY2_IP` | IP public của 3 server |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | cảnh báo Telegram |
| `GRAFANA_ADMIN_PASSWORD` | ≥ 12 ký tự |
| `HEALTHCHECKS_PING_URL` | (tuỳ chọn) heartbeat ngoài, xem mục 3 |
| `CONTROLLER_URL` | URL controller mà gateway/client dùng, ví dụ `https://ctl.example.com:8080` |
| `EGRESSA_GATEWAY_TOKEN`, `EGRESSA_CLIENT_TOKEN` | mỗi cái sinh bằng `openssl rand -hex 32` |
| `CONTROLLER_TLS_CERT`, `CONTROLLER_TLS_KEY` | nội dung PEM của chứng chỉ TLS cho controller |

- **PR / push nhánh khác**: `ops-ci` chạy yamllint, ansible-lint, syntax-check, shellcheck, `promtool check rules`, gitleaks. PR không được truy cập secret của production.
- **Merge vào `main`** (trừ khi chỉ sửa `*.md`/`docs/`): `ops-cd` build `controller` và `gateway` (`make build`, Go 1.26.4, linux/amd64) trên runner, rồi chạy Ansible:
  1. Hạ tầng: gateway từng máy một (**vpn-gw1 là canary**), sau đó controller.
  2. Ứng dụng: **controller trước** (gateway đăng ký vào nó), rồi từng gateway một để client kịp chuyển path khỏi gateway đang restart.
  3. `verify.yml`. Binary được lưu ở `/opt/egressa/releases/<sha256[:12]>/`, `current` là symlink; nếu binary không đổi thì không restart.
- Chạy tay: Actions → ops-cd → *Run workflow* (mode `check` = chỉ dry-run, tuỳ chọn `limit`).
- Muốn có cổng duyệt thủ công: thêm *Required reviewers* vào environment `production`.
- Bật *branch protection* cho `main` (yêu cầu `ops-ci` pass) để không merge được code chưa lint.

## 3. Cảnh báo (Alertmanager → Telegram)
 
> **Hiện Telegram đang TẮT** (`telegram_enabled: false` trong `inventory/group_vars/controller.yml`). Rule vẫn được Prometheus đánh giá và xem được qua tunnel (`ssh -L 9090:127.0.0.1:9090 ...` → mục Alerts, hoặc cổng 9093 cho Alertmanager). Bật lại: đặt `true`, thêm 2 secret Telegram, merge; token cũ trên server tự bị xoá khi tắt.
 
- Rule trong `roles/monitoring_stack/files/alerts.yml`: máy mất kết nối, dịch vụ ssh/fail2ban/auditd/ufw/docker chết, CPU/RAM/đĩa, đĩa sắp đầy trong 24h, lệch giờ, conntrack gần đầy (gateway), SSH brute-force, cần reboot > 3 ngày, điểm Lynis thấp.
- **Giới hạn cần biết:** nếu cả controller chết thì Prometheus cũng chết và *không có cảnh báo nào được gửi*. Rule `Watchdog` luôn bắn và được chuyển tới dịch vụ ngoài (healthchecks.io, miễn phí) – nếu heartbeat ngừng, dịch vụ đó nhắn cho bạn. Đặt `HEALTHCHECKS_PING_URL` để bật.

## 4. Truy cập Grafana / Prometheus

Các cổng 3000/9090/9093 chỉ bind `127.0.0.1` (Docker **bỏ qua UFW** nếu publish ra 0.0.0.0). Truy cập qua tunnel:

```
ssh -L 3000:127.0.0.1:3000 isQHung@<controller-ip>   # rồi mở http://localhost:3000
```
Import dashboard *Node Exporter Full* (ID 1860) trong Grafana. Mật khẩu admin chỉ có tác dụng ở lần khởi tạo đầu; đổi sau này bằng giao diện Grafana.

## 5. LVM / fstab (chạy tay, không đưa vào CD)

Chỉ chạy khi `sudo vgs` cho thấy VG còn dung lượng trống (hoặc bạn thêm đĩa mới, ví dụ `/dev/vdb`, vào `storage_pvs`). Chỉnh `roles/storage/defaults/main.yml` rồi:

```
ansible-playbook playbooks/storage.yml -e storage_enabled=true -e storage_vg=<vg> --limit vpn-gw1 -D
```
Làm từng máy, ngoài giờ cao điểm, có snapshot VPS. `/tmp` dùng `noexec`: nếu `apt` báo lỗi script, remount tạm `mount -o remount,exec /tmp`. `/home` chỉ có `nodev,nosuid` (không `noexec`).

## 6. Egressa trên server

| Thành phần | Chạy ở | Cổng (UFW) | Ghi chú |
|---|---|---|---|
| `egressa-controller` | controller, user `egressa` | `8080/tcp` mở cho mọi nơi (client ở khắp nơi) | **bắt buộc TLS** vì không có mạng riêng; xác thực bằng token |
| `egressa-gateway` | 2 gateway, **root** | `51820/udp` mở cho mọi nơi; **mọi UDP** từ IP của gateway còn lại (cổng backbone ngẫu nhiên) | `--id`, `--role`, `--uplink` lấy từ inventory |

- Binary tĩnh (`CGO_ENABLED=0`) build trên runner; server không clone/build. Đổi `EGRESSA_GOARCH` (script + workflow) nếu VPS là arm64.
- Tên gateway (`--id`, dùng ở `client --egress`) đặt trong `inventory/hosts.yml` (`egressa_id`); `--role` mặc định `access,egress` (`group_vars/gateways.yml`); `--uplink` tự lấy từ card mạng mặc định.
- Gateway tự thêm route/ip rule/iptables-NAT và dọn khi thoát (unit dùng SIGTERM, `TimeoutStopSec=30`). Vì vậy UFW ở gateway đặt `default routed = allow`, còn luồng vào chính máy vẫn `deny`.
- **Cần kiểm tra sau lần deploy đầu:** nếu probe/backbone đi qua card tunnel vào chính gateway, UFW sẽ chặn. Xem `/var/log/ufw.log` (`[UFW BLOCK] IN=<tên card>`), rồi khai báo card đó trong `ufw_allow_in_interfaces`.
- Policy: đặt file JSON và trỏ `egressa_policy_src` (controller sẽ chạy với `--policy`).
- **Rollback:** revert commit trên `main` (CD build lại bản cũ), hoặc trên server `ln -sfn /opt/egressa/releases/<id> /opt/egressa/current && systemctl restart egressa-gateway` (giữ 3 bản gần nhất).
- Binary `client` dành cho người dùng cuối, không triển khai bằng bộ này.

## 7. Quy ước an toàn

- `deploy` có sudo NOPASSWD (Ansible cần). Giữ private key chỉ trong GitHub Secrets; ai sửa được workflow là có quyền root trên cả 3 server → bật branch protection + review.
- `audit_immutable: true` (`-e 2`) khoá rule auditd tới khi reboot: chỉ bật khi cấu hình đã ổn định.
- Cập nhật phiên bản image trong `inventory/group_vars/controller.yml` (Prometheus/Alertmanager/Grafana) lên bản ổn định mới nhất trước lần deploy đầu.
- Lynis hằng tuần ghi `/var/log/lynis-report.dat`; xem gợi ý: `sudo lynis show details <ID>`.
