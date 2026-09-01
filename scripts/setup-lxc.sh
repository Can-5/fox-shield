#!/usr/bin/env bash
# fox-shield LXC setup — SYNPROXY + sysctl tuning + container hardening.
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

# --- 1b. Capability kontrolü (LXC unprivileged ise CAP_NET_ADMIN yok) ---
if [ "$SKIP_L3" -eq 0 ]; then
  if ! capsh --print 2>/dev/null | grep -q cap_net_admin; then
    warn "CAP_NET_ADMIN yok — SYNPROXY/nftables atlanıyor (unprivileged LXC)."
    SKIP_L3=1
  fi
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

# --- 4. Container hardening: capability drop + resource limits ---
# LXC config'ine eklenecek satırlar (unprivileged container'da bile geçerli).
LXC_CONF="/etc/fox-shield-lxc.conf"
cat > "$LXC_CONF" <<'EOF'
# fox-shield — LXC container hardening (lxc.container.conf içine kopyalanır)
# Yetki azaltma: shield container'ının ihtiyaç duymadığı capability'leri kapat.
lxc.cap.drop = mac_admin mac_override sys_time sys_module sys_rawio
# Kaynak limitleri: tek container'ın host'u tüketmesini engelle.
lxc.prlimit.nofile = soft:65535 hard:65535
lxc.prlimit.nproc = soft:1024 hard:2048
lxc.prlimit.core = 0
EOF
log "LXC hardening şablonu yazıldı: $LXC_CONF"

# --- 5. ulimit + cgroup limitleri (çalışan süreç için) ---
# Mevcut shell için ulimit uygula (başarısız olursa uyar, kritik değil).
ulimit -n 65535 2>/dev/null || warn "ulimit -n 65535 uygulanamadı."
ulimit -u 2048 2>/dev/null || warn "ulimit -u 2048 uygulanamadı."

# cgroup v2 varsa shield servisi için bellek/CPU limiti öner (systemd slice).
if [ -d /sys/fs/cgroup ]; then
  log "cgroup v2 mevcut — servis için MemoryMax/CPUQuota önerisi:"
  log "  systemctl set-property fox-shield.service MemoryMax=512M CPUQuota=200%"
fi

log "Kurulum tamam. L3 yoksa userspace shield (Docker) yeterli."
