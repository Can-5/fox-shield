#!/usr/bin/env bash
# fox-shield LXC setup — SYNPROXY + sysctl tuning.
#
# Hedef: LXC userspace-only. Privileged container yoksa SYNPROXY/nftables
# kurulamaz; bu script her adımı kontrol eder ve yetki yoksa güvenle atlar
# (safe fallback). Root değilse veya modüller yüklü değilse sadece sysctl
# userspace ayarlarını uygular.
set -euo pipefail

log() { echo "[fox-shield] $*"; }
warn() { echo "[fox-shield][warn] $*" >&2; }

# --- 1. Root kontrolü ---
if [ "$(id -u)" -ne 0 ]; then
  warn "root değilsiniz — SYNPROXY/nftables atlanıyor (userspace-only)."
  SKIP_L3=1
else
  SKIP_L3=0
fi

# --- 2. SYNPROXY (L3) — sadece privileged + modül varsa ---
if [ "$SKIP_L3" -eq 0 ]; then
  if modprobe nf_conntrack_sync 2>/dev/null && modprobe nf_synproxy 2>/dev/null; then
    log "SYNPROXY modülleri yüklendi."
    # SYNPROXY tablosu (örnek — gerçek ağ arayüzüne göre ayarlanır).
    # iptables -t raw -A PREROUTING -p tcp --dport 80 -j CT --notrack
    # iptables -t filter -A FORWARD -p tcp --dport 80 -m state --state INVALID -j DROP
    # iptables -t filter -A FORWARD -p tcp --dport 80 -m state --state UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
    log "SYNPROXY kuralları hazır (yorum satırı — arayüze göre etkinleştirin)."
  else
    warn "SYNPROXY modülleri yüklenemedi — L3 atlanıyor (userspace-only)."
  fi
fi

# --- 3. sysctl tuning (userspace-safe, her zaman uygulanır) ---
SYSCTL_CONF="/etc/sysctl.d/99-fox-shield.conf"
cat > "$SYSCTL_CONF" <<'EOF'
# fox-shield — DDoS dayanıklılığı (userspace-safe)
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
net.core.netdev_max_backlog = 8192
EOF

if [ "$SKIP_L3" -eq 0 ]; then
  sysctl --system >/dev/null 2>&1 && log "sysctl uygulandı: $SYSCTL_CONF" || warn "sysctl uygulanamadı."
else
  # Root değilsek sysctl dosyası yazılamaz — sadece bilgi ver.
  warn "sysctl dosyası yazılamadı (root değil). LXC'de root ile çalıştırın."
fi

log "Kurulum tamam. L3 yoksa userspace shield (Docker) yeterli."
