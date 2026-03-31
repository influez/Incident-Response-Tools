#!/bin/bash
# Ubuntu Incident Response Script v2.0
# Disesuaikan dengan NIST SP 800-86 & SANS DFIR Methodology
# Tested on Ubuntu 18.04, 20.04, 22.04, 24.04 LTS

# Konfigurasi Terminal, versi, & metadata
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

SCRIPT_VERSION="2.0"
SCRIPT_NAME="Ubuntu Incident Response Script"

log_info()    { echo -e "${GREEN}[✔] $(date '+%H:%M:%S') $1${NC}"; }
log_warn()    { echo -e "${YELLOW}[!] $(date '+%H:%M:%S') $1${NC}"; }
log_error()   { echo -e "${RED}[✘] $(date '+%H:%M:%S') $1${NC}"; }
log_phase()   { echo -e "\n${CYAN}${BOLD}════════════════════════════════════════════════════════${NC}"; \
                echo -e "${CYAN}${BOLD}  FASE: $1${NC}"; \
                echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════${NC}"; }

# Catat timestamp setiap fase
phase_start() {
    local phase_name="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] MULAI: $phase_name" >> "$dir/PROGRESS.log"
    log_phase "$phase_name"
}

phase_end() {
    local phase_name="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SELESAI: $phase_name" >> "$dir/PROGRESS.log"
    log_info "Fase '$phase_name' selesai."
}

# Bagian Error Handling
run_cmd() {
    local outfile="$1"
    shift
    "$@" > "$outfile" 2>>"$dir/ERRORS.log" || \
        echo "[PERINGATAN] Perintah gagal: $*" >> "$dir/ERRORS.log"
}

# Hash SHA256 dan tambahkan ke manifest
hash_file() {
    local filepath="$1"
    if [ -f "$filepath" ]; then
        sha256sum "$filepath" >> "$dir/manifest.sha256" 2>>"$dir/ERRORS.log"
    fi
}

# Cek apakah perintah tersedia
cmd_exists() { command -v "$1" &>/dev/null; }

# Enforce Root
if [ "$(id -u)" -ne 0 ]; then
    log_error "Skrip ini HARUS dijalankan sebagai root atau dengan sudo."
    log_error "Contoh: sudo bash $0"
    exit 1
fi

# Inisialisasi Direktori Output (timestamps)
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || echo "unknown")
OUTPUT_DIRNAME="UbuntuIR_${HOSTNAME_SHORT}_${TIMESTAMP}"
curr="${PWD}"
dir="${curr}/${OUTPUT_DIRNAME}"

mkdir -p "$dir" || { log_error "Gagal membuat direktori output: $dir"; exit 1; }

# Inisialisasi file log
touch "$dir/ERRORS.log"
touch "$dir/PROGRESS.log"
touch "$dir/manifest.sha256"

START_TIME=$(date '+%Y-%m-%d %H:%M:%S')

# Banner
clear
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║    Ubuntu Incident Response Script v${SCRIPT_VERSION}    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
log_info "Direktori output: $dir"
log_info "Waktu mulai     : $START_TIME"
log_info "Analis          : $(who am i 2>/dev/null | awk '{print $1}') (UID efektif: $(id))"
echo ""

# FASE 0 — METADATA KOLEKSI
phase_start "0 — METADATA KOLEKSI"

cat > "$dir/00.Metadata_Koleksi.txt" <<EOF
===============================================================
 METADATA INCIDENT RESPONSE
===============================================================
Nama Skrip      : $SCRIPT_NAME v$SCRIPT_VERSION
Waktu Mulai     : $START_TIME
Hostname        : $(hostname -f 2>/dev/null)
IP Address      : $(hostname -I 2>/dev/null | tr ' ' '\n' | head -5)
Analis/User     : $(who am i 2>/dev/null || echo "root session")
UID/GID         : $(id)
Kernel          : $(uname -r)
Versi Ubuntu    : $(lsb_release -d 2>/dev/null | cut -f2)
Arsitektur      : $(uname -m)
Uptime          : $(uptime -p 2>/dev/null || uptime)
Direktori Output: $dir
===============================================================
EOF

hash_file "$dir/00.Metadata_Koleksi.txt"
phase_end "0 — METADATA KOLEKSI"

# FASE 1 — INFORMASI SISTEM DASAR
phase_start "1 — INFORMASI SISTEM DASAR"

run_cmd "$dir/01.DateTime.txt"           date
run_cmd "$dir/02.Versi_Kernel.txt"       uname -a
run_cmd "$dir/03.Versi_OS.txt"           cat /etc/lsb-release
[ -f /etc/os-release ] && cat /etc/os-release >> "$dir/03.Versi_OS.txt" 2>>"$dir/ERRORS.log"
run_cmd "$dir/04.Uptime.txt"             uptime
run_cmd "$dir/05.Dmesg_Tail.txt"         dmesg | tail -200
run_cmd "$dir/06.Modul_Kernel.txt"       lsmod

for f in 01 02 03 04 05 06; do
    for ff in "$dir/${f}"*.txt; do hash_file "$ff"; done
done

phase_end "1 — INFORMASI SISTEM DASAR"

# FASE 2 — PROSES & MEMORI VOLATIL (Prioritas Tinggi — RFC Order of Volatility)
phase_start "2 — PROSES & MEMORI VOLATIL"

run_cmd "$dir/10.Daftar_Proses_Lengkap.txt"   ps auxef
run_cmd "$dir/11.Proses_Top.txt"              top -b -n 1
run_cmd "$dir/12.Proses_Tree.txt"             ps axjf

# Kumpulkan detail dari /proc untuk setiap PID yang aktif
PROC_DIR="$dir/proc_volatile"
mkdir -p "$PROC_DIR"
log_info "Mengumpulkan detail /proc per PID..."

for pid in /proc/[0-9]*/; do
    pidnum=$(basename "$pid")
    [ -d "/proc/$pidnum" ] || continue
    pdir="$PROC_DIR/pid_$pidnum"
    mkdir -p "$pdir"
    tr '\0' ' ' < "/proc/$pidnum/cmdline" > "$pdir/cmdline" 2>>"$dir/ERRORS.log"
    strings "/proc/$pidnum/environ" > "$pdir/environ" 2>>"$dir/ERRORS.log"
    cp "/proc/$pidnum/maps" "$pdir/maps" 2>>"$dir/ERRORS.log"
    cp "/proc/$pidnum/status" "$pdir/status" 2>>"$dir/ERRORS.log"
done

# Ringkasan: cari PID dengan path executable yg aneh (bukan di /usr, /bin, /sbin, /lib)
log_info "Mencari proses mencurigakan berdasarkan path executable..."
{
    echo "=== PID dengan Executable di Lokasi Tidak Umum ==="
    for pid in /proc/[0-9]*/; do
        pidnum=$(basename "$pid")
        exepath=$(readlink -f "/proc/$pidnum/exe" 2>/dev/null)
        if [ -n "$exepath" ]; then
            case "$exepath" in
                /usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/snap/*) ;;
                *) echo "PID=$pidnum EXE=$exepath" ;;
            esac
        fi
    done
    echo ""
    echo "=== PID dengan Executable yang Sudah Dihapus ==="
    for pid in /proc/[0-9]*/; do
        pidnum=$(basename "$pid")
        exepath=$(readlink "/proc/$pidnum/exe" 2>/dev/null)
        if echo "$exepath" | grep -q "(deleted)"; then
            cmdln=$(tr '\0' ' ' < "/proc/$pidnum/cmdline" 2>/dev/null)
            echo "PID=$pidnum EXE=$exepath CMD=$cmdln"
        fi
    done
} > "$dir/13.Proses_Mencurigakan.txt" 2>>"$dir/ERRORS.log"

# File descriptor yang terbuka per proses (ringkasan)
run_cmd "$dir/14.File_Descriptor_Terbuka.txt"  lsof -nP 2>/dev/null || echo "lsof tidak tersedia" > "$dir/14.File_Descriptor_Terbuka.txt"

for ff in "$dir/10."*.txt "$dir/11."*.txt "$dir/12."*.txt "$dir/13."*.txt "$dir/14."*.txt; do
    [ -f "$ff" ] && hash_file "$ff"
done

phase_end "2 — PROSES & MEMORI VOLATIL"

# FASE 3 — FORENSIK JARINGAN
phase_start "3 — FORENSIK JARINGAN"

# Gunakan ss sebagai command primer, netstat sebagai fallback
if cmd_exists ss; then
    run_cmd "$dir/20.Port_Listening.txt"        ss -tulnp
    run_cmd "$dir/21.Koneksi_Semua.txt"         ss -antp
    run_cmd "$dir/22.Koneksi_Established.txt"   ss -antp state established
    log_info "Menggunakan 'ss' untuk statistik jaringan"
else
    log_warn "'ss' tidak tersedia, menggunakan 'netstat' sebagai fallback"
    run_cmd "$dir/20.Port_Listening.txt"        netstat -tulnp
    run_cmd "$dir/21.Koneksi_Semua.txt"         netstat -antup
    run_cmd "$dir/22.Koneksi_Established.txt"   netstat -antup
    grep "ESTABLISHED" "$dir/22.Koneksi_Established.txt" > "${dir}/22.Koneksi_Established_filtered.txt" 2>>"$dir/ERRORS.log"
fi

run_cmd "$dir/23.ARP_Cache.txt"                 arp -an
run_cmd "$dir/24.Routing_Table.txt"             ip route show
run_cmd "$dir/25.Interface_Jaringan.txt"        ip link show
run_cmd "$dir/26.IP_Address.txt"                ip addr show
run_cmd "$dir/27.DNS_Resolver.txt"              cat /etc/resolv.conf
run_cmd "$dir/28.Hostname.txt"                  cat /etc/hostname
run_cmd "$dir/29.Hosts_File.txt"                cat /etc/hosts
run_cmd "$dir/30.Iptables_Rules.txt"            iptables -L -n -v
run_cmd "$dir/31.Iptables_NAT.txt"              iptables -t nat -L -n -v
run_cmd "$dir/32.Proc_Net_TCP.txt"              cat /proc/net/tcp
run_cmd "$dir/33.Proc_Net_TCP6.txt"             cat /proc/net/tcp6
run_cmd "$dir/34.Proc_Net_UDP.txt"              cat /proc/net/udp
run_cmd "$dir/35.Pengguna_Terkoneksi.txt"       w

for ff in "$dir/2"*.txt "$dir/3"*.txt; do [ -f "$ff" ] && hash_file "$ff"; done

phase_end "3 — FORENSIK JARINGAN"

# FASE 4 — PENGGUNA & AUTENTIKASI
phase_start "4 — PENGGUNA & AUTENTIKASI"

run_cmd "$dir/40.Daftar_User.txt"          cat /etc/passwd
run_cmd "$dir/41.User_Shell_Bash.txt"      grep -E '/bin/(ba)?sh|/bin/zsh|/usr/bin/fish' /etc/passwd
run_cmd "$dir/42.Daftar_Grup.txt"          cat /etc/group
run_cmd "$dir/43.Sudoers.txt"              cat /etc/sudoers
run_cmd "$dir/44.Sudoers_d.txt"            ls -la /etc/sudoers.d/ && cat /etc/sudoers.d/* 2>/dev/null
run_cmd "$dir/45.Lastlog.txt"              lastlog
run_cmd "$dir/46.Last_Login.txt"           last -F
run_cmd "$dir/47.Last_Bad_Login.txt"       lastb -F 2>/dev/null || echo "Tidak tersedia/akses terbatas" > "$dir/47.Last_Bad_Login.txt"
run_cmd "$dir/48.Faillog.txt"              faillog -a 2>/dev/null
run_cmd "$dir/49.Who_Online.txt"           who
run_cmd "$dir/50.Shadow_Metadata.txt"      cat /etc/shadow | awk -F: '{print $1, $2, $3, $4, $5, $6, $7, $8}' 2>/dev/null

# Kumpulkan history shell untuk semua pengguna dengan shell interaktif
HISTORY_DIR="$dir/shell_histories"
mkdir -p "$HISTORY_DIR"
log_info "Mengumpulkan riwayat shell semua pengguna..."

while IFS=: read -r uname _ uid gid _ homedir shell; do
    # Lewati pengguna sistem (UID < 1000) kecuali root
    if [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ]; then continue; fi
    case "$shell" in
        */bash|*/sh|*/zsh|*/fish|*/ksh|*/dash) ;;
        *) continue ;;
    esac
    histfile="$HISTORY_DIR/${uname}_history.txt"
    echo "=== History untuk: $uname (UID=$uid, Home=$homedir) ===" > "$histfile"
    for hfile in ".bash_history" ".zsh_history" ".sh_history" ".local/share/fish/fish_history"; do
        fullpath="$homedir/$hfile"
        if [ -f "$fullpath" ]; then
            echo "--- $fullpath ---" >> "$histfile"
            cat "$fullpath" >> "$histfile" 2>>"$dir/ERRORS.log"
        fi
    done
    hash_file "$histfile"
done < /etc/passwd

for ff in "$dir/4"*.txt "$dir/5"*.txt; do [ -f "$ff" ] && hash_file "$ff"; done

phase_end "4 — PENGGUNA & AUTENTIKASI"

# FASE 5 — PERSISTENSI & MEKANISME STARTUP
phase_start "5 — PERSISTENSI & MEKANISME STARTUP"

# Systemd services & timers
run_cmd "$dir/60.Systemd_Units_Semua.txt"       systemctl list-units --all --no-pager
run_cmd "$dir/61.Systemd_Services_Aktif.txt"    systemctl list-units --type=service --no-pager
run_cmd "$dir/62.Systemd_Timers.txt"            systemctl list-timers --all --no-pager
run_cmd "$dir/63.Systemd_Failed.txt"            systemctl --failed --no-pager

# Unit file yang diinstal secara manual
{
    echo "=== Unit Files di /etc/systemd/system/ ==="
    ls -la /etc/systemd/system/ 2>/dev/null
    echo ""
    echo "=== Unit Files di /lib/systemd/system/ (non-standar) ==="
    find /lib/systemd/system/ -newer /etc/passwd -ls 2>/dev/null
} > "$dir/64.Systemd_Unit_Files.txt"

# Crontabs
run_cmd "$dir/65.Cron_Etc.txt"                  ls -la /etc/cron* /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.monthly/ /etc/cron.weekly/ 2>/dev/null
run_cmd "$dir/66.Crontab_Root.txt"              crontab -l 2>/dev/null || echo "Tidak ada crontab untuk root"

CRON_DIR="$dir/crontabs_pengguna"
mkdir -p "$CRON_DIR"
log_info "Mengumpulkan crontab semua pengguna..."
if [ -d /var/spool/cron/crontabs ]; then
    cp -r /var/spool/cron/crontabs "$CRON_DIR/spool_crontabs" 2>>"$dir/ERRORS.log"
fi
if [ -d /var/spool/cron ]; then
    ls -la /var/spool/cron/ > "$CRON_DIR/daftar_spool_cron.txt" 2>>"$dir/ERRORS.log"
fi
if [ -d /etc/cron.d ]; then
    for f in /etc/cron.d/*; do
        [ -f "$f" ] && cp "$f" "$CRON_DIR/etccrond_$(basename $f)" 2>>"$dir/ERRORS.log"
    done
fi

run_cmd "$dir/67.At_Jobs.txt"   atq 2>/dev/null || echo "at tidak tersedia atau tidak ada jobs"

run_cmd "$dir/68.RC_Local.txt"   cat /etc/rc.local 2>/dev/null || echo "rc.local tidak ada"

# .bashrc / .profile / .bash_profile semua pengguna
PROFILE_DIR="$dir/profile_scripts"
mkdir -p "$PROFILE_DIR"
log_info "Mengumpulkan script profile semua pengguna..."
while IFS=: read -r uname _ uid _ _ homedir shell; do
    [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ] && continue
    case "$shell" in */bash|*/sh|*/zsh|*/fish|*/ksh|*/dash) ;; *) continue ;; esac
    for pfile in ".bashrc" ".bash_profile" ".profile" ".zshrc" ".zprofile"; do
        fullpath="$homedir/$pfile"
        if [ -f "$fullpath" ]; then
            destfile="$PROFILE_DIR/${uname}_$(echo $pfile | tr '.' '_').txt"
            echo "=== $fullpath ===" > "$destfile"
            cat "$fullpath" >> "$destfile" 2>>"$dir/ERRORS.log"
            hash_file "$destfile"
        fi
    done
done < /etc/passwd

# SSH authorized_keys semua pengguna
SSH_KEYS_DIR="$dir/ssh_authorized_keys"
mkdir -p "$SSH_KEYS_DIR"
log_info "Mengumpulkan SSH authorized_keys semua pengguna..."
while IFS=: read -r uname _ uid _ _ homedir _; do
    akfile="$homedir/.ssh/authorized_keys"
    if [ -f "$akfile" ]; then
        destfile="$SSH_KEYS_DIR/${uname}_authorized_keys.txt"
        echo "=== $akfile ===" > "$destfile"
        cat "$akfile" >> "$destfile" 2>>"$dir/ERRORS.log"
        hash_file "$destfile"
    fi
done < /etc/passwd

for ff in "$dir/6"*.txt; do [ -f "$ff" ] && hash_file "$ff"; done

phase_end "5 — PERSISTENSI & MEKANISME STARTUP"

# FASE 6 — FORENSIK SSH
phase_start "6 — FORENSIK SSH"

run_cmd "$dir/70.SSHD_Config.txt"          cat /etc/ssh/sshd_config
run_cmd "$dir/71.SSH_Config_Global.txt"    cat /etc/ssh/ssh_config
run_cmd "$dir/72.SSH_Known_Hosts.txt"      cat /etc/ssh/ssh_known_hosts 2>/dev/null

# Percobaan login SSH dari auth.log
{
    echo "=== Percobaan Login SSH Gagal ==="
    grep -h "Failed password\|Invalid user\|authentication failure" /var/log/auth.log /var/log/auth.log.* 2>/dev/null | tail -500
    echo ""
    echo "=== Login SSH Berhasil ==="
    grep -h "Accepted\|session opened for user" /var/log/auth.log /var/log/auth.log.* 2>/dev/null | tail -200
    echo ""
    echo "=== Port Forwarding SSH ==="
    grep -h "port_forwarding\|Forwarding" /var/log/auth.log /var/log/auth.log.* 2>/dev/null | tail -100
} > "$dir/73.SSH_Login_Attempts.txt" 2>>"$dir/ERRORS.log"

# Kumpulkan known_hosts per pengguna
KNOWN_HOSTS_DIR="$dir/ssh_known_hosts"
mkdir -p "$KNOWN_HOSTS_DIR"
while IFS=: read -r uname _ uid _ _ homedir _; do
    khfile="$homedir/.ssh/known_hosts"
    if [ -f "$khfile" ]; then
        destfile="$KNOWN_HOSTS_DIR/${uname}_known_hosts.txt"
        echo "=== $khfile ===" > "$destfile"
        cat "$khfile" >> "$destfile" 2>>"$dir/ERRORS.log"
        hash_file "$destfile"
    fi
done < /etc/passwd

for ff in "$dir/7"*.txt; do [ -f "$ff" ] && hash_file "$ff"; done

phase_end "6 — FORENSIK SSH"

# FASE 7 — LOG SISTEM & AUDIT
phase_start "7 — LOG SISTEM & AUDIT"

LOG_DIR="$dir/logs_sistem"
mkdir -p "$LOG_DIR"

# Salin log penting
for logfile in auth.log syslog kern.log dpkg.log apt/history.log ufw.log fail2ban.log; do
    src="/var/log/$logfile"
    if [ -f "$src" ]; then
        dest="$LOG_DIR/$(echo $logfile | tr '/' '_')"
        cp "$src" "$dest" 2>>"$dir/ERRORS.log"
        hash_file "$dest"
        log_info "Disalin: $src"
    fi
done

# Salin rotasi log (*.gz tidak diekstrak, hanya dicopy untuk chain of custody)
for logglob in /var/log/auth.log.* /var/log/syslog.*; do
    [ -f "$logglob" ] && cp "$logglob" "$LOG_DIR/" 2>>"$dir/ERRORS.log"
done

# Journalctl — 72 jam terakhir
log_info "Mengekspor journalctl 72 jam terakhir..."
journalctl --since "72 hours ago" --no-pager > "$LOG_DIR/journalctl_72jam.txt" 2>>"$dir/ERRORS.log"
journalctl -k --no-pager > "$LOG_DIR/journalctl_kernel.txt" 2>>"$dir/ERRORS.log"
journalctl _COMM=sudo --no-pager > "$LOG_DIR/journalctl_sudo.txt" 2>>"$dir/ERRORS.log"

# Auditd — jika tersedia
if cmd_exists ausearch; then
    log_info "auditd terdeteksi, mengekspor audit logs..."
    ausearch -i > "$LOG_DIR/ausearch_all.txt" 2>>"$dir/ERRORS.log"
    ausearch -m execve -i > "$LOG_DIR/ausearch_execve.txt" 2>>"$dir/ERRORS.log"
    ausearch -m user_login -i > "$LOG_DIR/ausearch_login.txt" 2>>"$dir/ERRORS.log"
else
    log_warn "auditd/ausearch tidak tersedia — dilewati"
fi

# wtmp & btmp (binary — decode dengan last/lastb)
run_cmd "$dir/80.Wtmp_Decoded.txt"         last -F -f /var/log/wtmp 2>/dev/null
run_cmd "$dir/81.Btmp_Decoded.txt"         lastb -F -f /var/log/btmp 2>/dev/null || echo "Akses terbatas atau tidak ada"

# Hashing log files
for ff in "$LOG_DIR"/*; do [ -f "$ff" ] && hash_file "$ff"; done
for ff in "$dir/8"*.txt; do [ -f "$ff" ] && hash_file "$ff"; done

phase_end "7 — LOG SISTEM & AUDIT"

# FASE 8 — FILESYSTEM & INTEGRITAS
phase_start "8 — FILESYSTEM & INTEGRITAS"

# Direktori listing
run_cmd "$dir/90.Homedir_Listing.txt"         ls -alrtR /home
run_cmd "$dir/91.VarWWW_Listing.txt"          ls -alrtR /var/www 2>/dev/null
run_cmd "$dir/92.Tmp_Listing.txt"             ls -alrt /tmp /dev/shm /var/tmp

# File di direktori temporary
{
    echo "=== File di /tmp ==="
    find /tmp -type f -ls 2>/dev/null
    echo ""
    echo "=== File di /dev/shm ==="
    find /dev/shm -type f -ls 2>/dev/null
    echo ""
    echo "=== File di /var/tmp ==="
    find /var/tmp -type f -ls 2>/dev/null
} > "$dir/93.File_Tmp_Detail.txt" 2>>"$dir/ERRORS.log"

# File yang dimodifikasi dalam 3 hari terakhir (eksklusikan /proc dan /sys)
log_info "Mencari file yang dimodifikasi dalam 72 jam terakhir (proses ini mungkin memerlukan waktu)..."
find / -mtime -3 \
    -not -path "/proc/*" \
    -not -path "/sys/*" \
    -not -path "/dev/*" \
    -not -path "${dir}/*" \
    -not -path "/run/*" \
    -ls 2>/dev/null > "$dir/94.File_Modified_72jam.txt"

# SUID dan SGID files
log_info "Mencari file SUID/SGID..."
find / \( -perm -4000 -o -perm -2000 \) \
    -not -path "/proc/*" \
    -not -path "/sys/*" \
    -ls 2>/dev/null > "$dir/95.SUID_SGID_Files.txt"

# World-writable directories
log_info "Mencari direktori world-writable..."
find / -type d -perm -0002 \
    -not -path "/proc/*" \
    -not -path "/sys/*" \
    -not -path "/dev/*" \
    -ls 2>/dev/null > "$dir/96.WorldWritable_Dirs.txt"

# File tersembunyi di direktori yg krusial
{
    echo "=== File Tersembunyi di /etc ==="
    find /etc -name ".*" -ls 2>/dev/null
    echo ""
    echo "=== File Tersembunyi di /root ==="
    find /root -name ".*" -ls 2>/dev/null
    echo ""
    echo "=== File Tersembunyi di /home ==="
    find /home -name ".*" -ls 2>/dev/null
} > "$dir/97.File_Tersembunyi.txt" 2>>"$dir/ERRORS.log"

for ff in "$dir/9"*.txt; do [ -f "$ff" ] && hash_file "$ff"; done

phase_end "8 — FILESYSTEM & INTEGRITAS"

# FASE 9 — PAKET & PERANGKAT LUNAK
phase_start "9 — PAKET & PERANGKAT LUNAK"

run_cmd "$dir/100.Daftar_Paket_Dpkg.txt"       dpkg -l
run_cmd "$dir/101.Paket_Terinstall_Baru.txt"   grep " install " /var/log/dpkg.log 2>/dev/null | tail -200

# Snap packages
if cmd_exists snap; then
    run_cmd "$dir/102.Snap_List.txt"            snap list
else
    echo "snap tidak tersedia" > "$dir/102.Snap_List.txt"
fi

# Pip packages (tanpa instalasi)
if cmd_exists pip3; then
    run_cmd "$dir/103.Python_Packages.txt"      pip3 list 2>/dev/null
elif cmd_exists pip; then
    run_cmd "$dir/103.Python_Packages.txt"      pip list 2>/dev/null
fi

# Gem (Ruby)
if cmd_exists gem; then
    run_cmd "$dir/104.Ruby_Gems.txt"            gem list 2>/dev/null
fi

for ff in "$dir/10"*.txt; do [ -f "$ff" ] && hash_file "$ff"; done

phase_end "9 — PAKET & PERANGKAT LUNAK"

# FASE 10 — DOCKER & CONTAINER
phase_start "10 — DOCKER & CONTAINER"

if cmd_exists docker; then
    log_info "Docker terdeteksi, mengumpulkan informasi container..."
    run_cmd "$dir/110.Docker_Containers.txt"    docker ps -a
    run_cmd "$dir/111.Docker_Images.txt"        docker images
    run_cmd "$dir/112.Docker_Networks.txt"      docker network ls
    run_cmd "$dir/113.Docker_Volumes.txt"       docker volume ls
    run_cmd "$dir/114.Docker_Info.txt"          docker info
else
    log_warn "Docker tidak terinstall — melewati fase container"
    echo "Docker tidak terinstall" > "$dir/110.Docker_Containers.txt"
fi

# Linux namespaces (isolasi container/proses)
if cmd_exists lsns; then
    run_cmd "$dir/115.Linux_Namespaces.txt"     lsns
else
    echo "lsns tidak tersedia" > "$dir/115.Linux_Namespaces.txt"
fi

for ff in "$dir/11"*.txt; do [ -f "$ff" ] && hash_file "$ff"; done

phase_end "10 — DOCKER & CONTAINER"

# FASE 11 — PENCARIAN BACKDOOR & MALWARE
phase_start "11 — PENCARIAN BACKDOOR & MALWARE"

BACKDOOR_DIR="$dir/backdoor_results"
mkdir -p "$BACKDOOR_DIR"

# === PHP Backdoor Patterns ===
log_info "Memindai pola PHP backdoor..."
grep -RPn \
    "(passthru|shell_exec|system|phpinfo|base64_decode|chmod|mkdir|fopen|fclose|readfile|eval|exec|popen|proc_open|assert|preg_replace.*\/e) *\(" \
    /home/ /var/www/ /tmp/ /dev/shm/ /var/tmp/ \
    > "$BACKDOOR_DIR/php_backdoor_patterns.txt" 2>>"$dir/ERRORS.log"

# === Python Malware Patterns ===
log_info "Memindai pola Python berbahaya..."
grep -RPn \
    "(subprocess\.call|os\.system|exec\(|eval\(|__import__\(|pty\.spawn|socket\.connect|base64\.b64decode|compile\(.*exec)" \
    /home/ /var/www/ /tmp/ /dev/shm/ /var/tmp/ \
    > "$BACKDOOR_DIR/python_malware_patterns.txt" 2>>"$dir/ERRORS.log"

# === Perl Malware Patterns ===
log_info "Memindai pola Perl berbahaya..."
grep -RPn \
    "(system\s*\(|exec\s*\(|`.*`|socket\s*\(|SOCK_STREAM|base64_decode|eval\s*\()" \
    /home/ /var/www/ /tmp/ /dev/shm/ /var/tmp/ \
    > "$BACKDOOR_DIR/perl_malware_patterns.txt" 2>>"$dir/ERRORS.log"

# === Lua Patterns ===
log_info "Memindai pola Lua berbahaya..."
grep -RPn \
    "(os\.execute|io\.popen|loadstring|dofile|require.*socket)" \
    /home/ /var/www/ /tmp/ /dev/shm/ /var/tmp/ \
    > "$BACKDOOR_DIR/lua_malware_patterns.txt" 2>>"$dir/ERRORS.log"

# === Base64 Encoded Payloads ===
log_info "Memindai payload base64 mencurigakan..."
grep -RPn \
    "(echo\s+[A-Za-z0-9+/=]{50,}\s*\|\s*base64\s+-d|base64\s+-d\s*<<<|base64\s+--decode)" \
    /home/ /var/www/ /tmp/ /dev/shm/ /var/tmp/ /etc/ \
    > "$BACKDOOR_DIR/base64_payloads.txt" 2>>"$dir/ERRORS.log"

# === curl/wget piped to bash (dropper pattern) ===
log_info "Memindai pola dropper (curl/wget pipe ke bash)..."
grep -RPn \
    "(curl.*\|\s*(ba)?sh|wget.*\|\s*(ba)?sh|fetch.*\|\s*(ba)?sh|curl.*>.*\.(sh|py|pl)|wget.*-O.*\.(sh|py|pl))" \
    /home/ /var/www/ /tmp/ /dev/shm/ /var/tmp/ /etc/ \
    > "$BACKDOOR_DIR/dropper_patterns.txt" 2>>"$dir/ERRORS.log"

# === Webshell signatures sederhana ===
log_info "Memindai tanda tangan webshell umum..."
grep -RPnil \
    "(r57|c99|WSO|b374k|FilesMan|indoxploit|phpspy|alfa|madspot|wso shell)" \
    /home/ /var/www/ /tmp/ /dev/shm/ /var/tmp/ \
    > "$BACKDOOR_DIR/webshell_signatures.txt" 2>>"$dir/ERRORS.log"

# === Reverse shell indicators ===
log_info "Memindai indikator reverse shell..."
grep -RPn \
    "(/dev/tcp/|/dev/udp/|nc\s+-e|ncat\s+-e|bash\s+-i\s+>&|0>&1|mkfifo.*nc|socat.*EXEC)" \
    /home/ /var/www/ /tmp/ /dev/shm/ /var/tmp/ /etc/ \
    > "$BACKDOOR_DIR/reverse_shell_indicators.txt" 2>>"$dir/ERRORS.log"

# === Crontab entries mencurigakan (curl/wget) ===
{
    echo "=== Crontab Berisi curl/wget ==="
    grep -rn "curl\|wget\|nc \|ncat\|python.*-c\|perl.*-e" \
        /etc/cron* /var/spool/cron/ 2>/dev/null
} > "$BACKDOOR_DIR/cron_mencurigakan.txt" 2>>"$dir/ERRORS.log"

for ff in "$BACKDOOR_DIR"/*; do [ -f "$ff" ] && hash_file "$ff"; done

phase_end "11 — PENCARIAN BACKDOOR & MALWARE"

# FASE 12 — DIREKTORI & LISTING PENTING
phase_start "12 — DIREKTORI & LISTING PENTING"

{
    echo "=== /etc/init.d/ ==="
    ls -la /etc/init.d/ 2>/dev/null
    echo ""
    echo "=== /etc/profile.d/ ==="
    ls -la /etc/profile.d/ 2>/dev/null
    cat /etc/profile.d/*.sh 2>/dev/null
    echo ""
    echo "=== /etc/ld.so.preload (LD_PRELOAD persistence) ==="
    cat /etc/ld.so.preload 2>/dev/null || echo "Tidak ada"
    echo ""
    echo "=== /etc/ld.so.conf.d/ ==="
    ls -la /etc/ld.so.conf.d/ 2>/dev/null
    cat /etc/ld.so.conf.d/*.conf 2>/dev/null
} > "$dir/120.File_Konfigurasi_Penting.txt" 2>>"$dir/ERRORS.log"

# Binary yang baru dimodifikasi di path sistem
{
    echo "=== Binary Sistem yang Dimodifikasi dalam 7 Hari Terakhir ==="
    find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \
        -type f -mtime -7 -ls 2>/dev/null
} > "$dir/121.Binary_Sistem_Baru.txt" 2>>"$dir/ERRORS.log"

hash_file "$dir/120.File_Konfigurasi_Penting.txt"
hash_file "$dir/121.Binary_Sistem_Baru.txt"

phase_end "12 — DIREKTORI & LISTING PENTING"

# FASE 13 — FINALISASI & TRIAGE SUMMARY
phase_start "13 — TRIAGE SUMMARY"

END_TIME=$(date '+%Y-%m-%d %H:%M:%S')

# Hitung statistik untuk summary
ESTABLISHED_COUNT=$(grep -c "ESTABLISHED\|estab" "$dir/22.Koneksi_Established.txt" 2>/dev/null || echo 0)
BASH_USER_COUNT=$(wc -l < "$dir/41.User_Shell_Bash.txt" 2>/dev/null || echo 0)
RECENT_FILES_COUNT=$(wc -l < "$dir/94.File_Modified_72jam.txt" 2>/dev/null || echo 0)
SUID_COUNT=$(wc -l < "$dir/95.SUID_SGID_Files.txt" 2>/dev/null || echo 0)
CRON_COUNT=$(find /etc/cron* /var/spool/cron -type f 2>/dev/null | wc -l || echo 0)

# Hitung temuan backdoor
PHP_HITS=$(wc -l < "$BACKDOOR_DIR/php_backdoor_patterns.txt" 2>/dev/null || echo 0)
PYTHON_HITS=$(wc -l < "$BACKDOOR_DIR/python_malware_patterns.txt" 2>/dev/null || echo 0)
DROPPER_HITS=$(wc -l < "$BACKDOOR_DIR/dropper_patterns.txt" 2>/dev/null || echo 0)
REVSHELL_HITS=$(wc -l < "$BACKDOOR_DIR/reverse_shell_indicators.txt" 2>/dev/null || echo 0)
WEBSHELL_HITS=$(wc -l < "$BACKDOOR_DIR/webshell_signatures.txt" 2>/dev/null || echo 0)
TOTAL_BACKDOOR=$((PHP_HITS + PYTHON_HITS + DROPPER_HITS + REVSHELL_HITS + WEBSHELL_HITS))

# Proses dengan executable terhapus
DELETED_EXE_COUNT=$(grep -c "deleted" "$dir/13.Proses_Mencurigakan.txt" 2>/dev/null || echo 0)

cat > "$dir/SUMMARY.txt" <<SUMMARY

UBUNTU IR — LAPORAN SINGKAT TRIAGE
$SCRIPT_NAME v$SCRIPT_VERSION

INFORMASI KOLEKSI
─────────────────────────────────────────────────────────────
Hostname        : $(hostname -f 2>/dev/null)
IP Address      : $(hostname -I 2>/dev/null | tr ' ' ' ')
Kernel          : $(uname -r)
OS              : $(lsb_release -d 2>/dev/null | cut -f2)
Waktu Mulai     : $START_TIME
Waktu Selesai   : $END_TIME
Analis          : $(who am i 2>/dev/null || echo "root/non-login session")
Direktori Output: $dir

STATISTIK TEMUAN
─────────────────────────────────────────────────────────────
[Jaringan]
  Koneksi ESTABLISHED               : $ESTABLISHED_COUNT

[Pengguna]
  User dengan Shell Bash/Interaktif : $BASH_USER_COUNT

[Filesystem]
  File dimodifikasi (72 jam)        : $RECENT_FILES_COUNT baris
  File SUID/SGID                    : $SUID_COUNT entri

[Persistensi]
  Total file Crontab                : $CRON_COUNT

[Proses Mencurigakan]
  Proses dengan executable dihapus  : $DELETED_EXE_COUNT

TEMUAN POTENSI BACKDOOR/MALWARE
─────────────────────────────────────────────────────────────
  Pola PHP Backdoor                 : $PHP_HITS baris
  Pola Python Berbahaya             : $PYTHON_HITS baris
  Pola Dropper (curl/wget|bash)     : $DROPPER_HITS baris
  Indikator Reverse Shell           : $REVSHELL_HITS baris
  Tanda Tangan Webshell             : $WEBSHELL_HITS baris
  ─────────────────────────────────────────────────────────
  TOTAL INDIKATOR POTENSI MALWARE   : $TOTAL_BACKDOOR baris

PRIORITAS INVESTIGASI LANJUTAN
─────────────────────────────────────────────────────────────
$(if [ "$DELETED_EXE_COUNT" -gt 0 ]; then echo "  ⚠ [CRITICAL] Ditemukan $DELETED_EXE_COUNT proses dengan executable TERHAPUS — periksa $dir/13.Proses_Mencurigakan.txt"; fi)
$(if [ "$REVSHELL_HITS" -gt 0 ]; then echo "  ⚠ [CRITICAL] Ditemukan $REVSHELL_HITS indikator reverse shell — periksa $BACKDOOR_DIR/reverse_shell_indicators.txt"; fi)
$(if [ "$DROPPER_HITS" -gt 0 ]; then echo "  ⚠ [HIGH] Ditemukan $DROPPER_HITS indikator dropper — periksa $BACKDOOR_DIR/dropper_patterns.txt"; fi)
$(if [ "$WEBSHELL_HITS" -gt 0 ]; then echo "  ⚠ [HIGH] Ditemukan $WEBSHELL_HITS tanda tangan webshell — periksa $BACKDOOR_DIR/webshell_signatures.txt"; fi)
$(if [ "$PHP_HITS" -gt 0 ]; then echo "  ⚠ [MEDIUM] Ditemukan $PHP_HITS pola PHP backdoor — periksa $BACKDOOR_DIR/php_backdoor_patterns.txt"; fi)
$(if [ "$ESTABLISHED_COUNT" -gt 20 ]; then echo "  ⚠ [WARNING] Jumlah koneksi ESTABLISHED tinggi ($ESTABLISHED_COUNT) — periksa $dir/22.Koneksi_Established.txt"; fi)

CHAIN OF CUSTODY
─────────────────────────────────────────────────────────────
  Manifest SHA256 : $dir/manifest.sha256
  Error Log       : $dir/ERRORS.log
  Progress Log    : $dir/PROGRESS.log

SUMMARY

log_info "SUMMARY dibuat: $dir/SUMMARY.txt"
hash_file "$dir/SUMMARY.txt"

# Finalisasi metadata dengan waktu selesai
echo "Waktu Selesai : $END_TIME" >> "$dir/00.Metadata_Koleksi.txt"

phase_end "13 — TRIAGE SUMMARY"

# KOMPRES & FINALISASI
log_phase "FINALISASI — KOMPRESI PAKET BUKTI"

ARCHIVE_NAME="UbuntuIR_${HOSTNAME_SHORT}_${TIMESTAMP}.tar.gz"
log_info "Membuat arsip terkompresi: $ARCHIVE_NAME ..."

cd "$curr" || exit 1
tar -czf "$ARCHIVE_NAME" "$OUTPUT_DIRNAME" 2>>"$dir/ERRORS.log"

if [ -f "$ARCHIVE_NAME" ]; then
    ARCHIVE_HASH=$(sha256sum "$ARCHIVE_NAME" | awk '{print $1}')
    log_info "Arsip berhasil dibuat: $ARCHIVE_NAME"
    log_info "SHA256 Arsip: $ARCHIVE_HASH"
    echo ""
    echo -e "${BOLD}SHA256 Arsip Final: $ARCHIVE_HASH${NC}" | tee -a "$dir/manifest.sha256"
else
    log_error "Gagal membuat arsip! Direktori mentah tersimpan di: $dir"
fi

# FINAL OUTPUT
echo ""
echo -e "${BOLD}${GREEN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              KOLEKSI IR SELESAI                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  ${GREEN}Direktori Bukti : ${BOLD}$dir${NC}"
echo -e "  ${GREEN}Arsip           : ${BOLD}${curr}/${ARCHIVE_NAME}${NC}"
echo -e "  ${GREEN}Manifest SHA256 : ${BOLD}$dir/manifest.sha256${NC}"
echo -e "  ${YELLOW}Error Log       : ${BOLD}$dir/ERRORS.log${NC}"
echo -e "  ${CYAN}Laporan Triage  : ${BOLD}$dir/SUMMARY.txt${NC}"
echo ""
echo -e "  ${BOLD}Waktu Mulai  : $START_TIME${NC}"
echo -e "  ${BOLD}Waktu Selesai: $END_TIME${NC}"
echo ""
echo -e "${YELLOW}  PERINGATAN: Direktori mentah TIDAK dihapus.${NC}"
echo -e "${YELLOW}  Hapus manual setelah verifikasi jika diperlukan.${NC}"
echo ""
