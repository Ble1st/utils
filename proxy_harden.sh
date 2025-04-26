#!/bin/bash
set -euo pipefail

SCRIPT_VERSION="1.4"
LOGFILE="/var/log/proxmox_hardening.log"

# === Konfigurierbare Variablen ===
PROXMOX_USER="test" # Proxmox-Admin-Benutzer
EMAIL="$PROXMOX_USER@localhost"
DISABLE_SERVICES=("telnet") # Zu deaktivierende Dienste (erweiterbar)

# === Hilfsfunktionen ===

log() {
    local msg="$1"
    echo "$(date '+%F %T') [$SCRIPT_VERSION] $msg" | tee -a "$LOGFILE"
    logger -t proxmox_hardening "$msg"
}

backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        cp "$file" "${file}.bak.$(date +%F-%H%M%S)"
        log "Backup von $file erstellt."
    fi
}

add_unique_line() {
    local line="$1"
    local file="$2"
    grep -qxF "$line" "$file" || echo "$line" >> "$file"
}

safe_add_to_fstab() {
    local entry="$1"
    local mountpoint="$2"
    if ! grep -q "$mountpoint" /etc/fstab; then
        echo "$entry" >> /etc/fstab
        log "fstab: $mountpoint gesichert."
    fi
}

create_cronjob_once() {
    local cronfile="$1"
    local content="$2"
    if [ ! -f "$cronfile" ]; then
        echo "$content" > "$cronfile"
        chmod +x "$cronfile"
        log "Cronjob $cronfile erstellt."
    fi
}

# === Sudo-Prüfung ===
if [ "$(id -u)" -ne 0 ]; then
    log "Dieses Skript muss als root ausgeführt werden (z.B. mit sudo)."
    exit 1
fi

log "Starte Proxmox-Hardening-Skript Version $SCRIPT_VERSION."

# === Prüfen, ob Proxmox erkannt wird ===
if [ ! -d /etc/pve ]; then
    log "Warnung: Proxmox scheint auf diesem System nicht installiert zu sein (/etc/pve fehlt)."
fi

# === Backup wichtiger Konfigurationsdateien ===
FILES_TO_BACKUP=(
    "/etc/ssh/sshd_config"
    "/etc/fstab"
    "/etc/sysctl.conf"
    "/etc/aliases"
    "/etc/postfix/main.cf"
)
for file in "${FILES_TO_BACKUP[@]}"; do
    backup_file "$file"
done

# === Postfix installieren & konfigurieren ===
export DEBIAN_FRONTEND=noninteractive
apt-get update
debconf-set-selections <<< "postfix postfix/mailname string $(hostname)"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Local only'"
apt-get install -y postfix
if [ -f /etc/postfix/main.cf ]; then
    sed -i "s/^mydestination.*/mydestination = localhost/" /etc/postfix/main.cf
    systemctl restart postfix
fi
log "Postfix installiert und konfiguriert."

# === Nicht benötigte Dienste deaktivieren ===
for service in "${DISABLE_SERVICES[@]}"; do
    if systemctl list-unit-files | grep -qw "$service"; then
        systemctl disable --now "$service"
        log "Dienst $service deaktiviert."
    fi
done

# === Automatische Updates (unattended-upgrades) einrichten ===
apt-get install -y unattended-upgrades
cat <<EOF > /etc/apt/apt.conf.d/51unattended-upgrades-proxmox-blacklist
Unattended-Upgrade::Allowed-Origins {
    "origin=Debian,codename=\${distro_codename},label=Debian-Security";
};
Unattended-Upgrade::Package-Blacklist {
    "proxmox-ve";
    "pve-kernel";
    "pve-manager";
    "pve-enterprise-repo";
    "pve-firmware";
};
EOF
dpkg-reconfigure -plow unattended-upgrades
log "Automatische Updates und Proxmox-Blacklist eingerichtet."

# === Mailweiterleitung für root einrichten ===
sed -i '/^root:/d' /etc/aliases
add_unique_line "root: $EMAIL" /etc/aliases
newaliases
log "Mailweiterleitung für root eingerichtet."

# === Logwatch einrichten ===
apt-get install -y logwatch
create_cronjob_once "/etc/cron.weekly/00logwatch" "#!/bin/bash
/usr/sbin/logwatch --output mail --mailto $EMAIL --detail high
"

# === Fail2ban (inkl. Proxmox) ===
apt-get install -y fail2ban
cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 3
destemail = $EMAIL
sender = fail2ban@$(hostname)
mta = sendmail

[sshd]
enabled = true
port = ssh
backend = systemd
maxretry = 3
bantime = 600
findtime = 600

[proxmox]
enabled = true
port = 8006
filter = proxmox
logpath = /var/log/pveproxy/access.log
maxretry = 3
EOF

cat <<EOF > /etc/fail2ban/filter.d/proxmox.conf
[Definition]
failregex = .*authentication failure;.*user=<F-USER>.*
ignoreregex =
EOF

systemctl enable --now fail2ban
log "Fail2ban installiert und konfiguriert."

# === AppArmor installieren & aktivieren ===
apt-get install -y apparmor apparmor-profiles apparmor-utils
if lsmod | grep -q apparmor; then
    systemctl enable --now apparmor
    log "AppArmor aktiviert."
fi

# === Kernel-Hardening nach BSI/NITS Empfehlungen ===
cat <<EOF > /etc/sysctl.d/99-proxmox-hardening.conf
# Cluster-Konfiguration erlauben: IPv4 und IPv6 Forwarding aktivieren!
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
# Packet Redirect deaktivieren
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# Routed Packets nicht akzeptieren
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# ICMP Redirects nicht akzeptieren
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# Secure ICMP Redirects nicht akzeptieren
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
# Suspicious Packets müssen geloggt werden
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
# Broadcast ICMP Requests müssen ignoriert werden
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Bogus ICMP Responses müssen ignoriert werden
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Reverse Path Filtering aktivieren
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# TCP SYN Cookies müssen aktiviert werden
net.ipv4.tcp_syncookies = 1
# IPv6 deaktivieren (optional, hier aktiviert für Cluster)
# net.ipv6.conf.all.disable_ipv6 = 1
# IPv6 Router Advertisements deaktivieren
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
# Memory Protection
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
vm.swappiness = 10
vm.mmap_min_addr = 65536
# Disable uncommon protocols
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
# Core Dumps deaktivieren
fs.suid_dumpable = 0
EOF

# Explizit auch sofort Forwarding aktivieren
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
log "Cluster-Konfiguration: IPv4 und IPv6 Forwarding aktiviert (sofort und persistent)."

# Einstellungen anwenden
sysctl --system

# === Fstab-Hardening: /tmp und /dev/shm sichern ===
safe_add_to_fstab "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" "/tmp"
safe_add_to_fstab "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" "/dev/shm"
mount -o remount /tmp || true
mount -o remount /dev/shm || true

# === Auditd installieren & aktivieren ===
apt-get install -y auditd
systemctl enable --now auditd
log "Auditd installiert und aktiviert."

# === Auditd-Regeln für Proxmox und kritische Dateien ===
cat <<EOF > /etc/audit/rules.d/proxmox-critical.rules
-w /etc/pve/ -p wa -k proxmox_conf_change
-w /etc/passwd -p wa -k passwd_change
-w /etc/shadow -p wa -k shadow_change
-w /etc/ssh/sshd_config -p wa -k sshd_config_change
-w /etc/network/interfaces -p wa -k netif_change
EOF
augenrules --load
log "Auditd-Regeln für kritische Dateien eingerichtet."

# === AIDE installieren & einrichten ===
apt-get install -y aide
aideinit || true
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db || true
create_cronjob_once "/etc/cron.daily/aide" "#!/bin/bash
/usr/bin/aide.wrapper --check
"
log "AIDE installiert und eingerichtet."

# === Rootkit Hunter installieren & konfigurieren ===
apt-get install -y rkhunter
rkhunter --update || true
rkhunter --propupd -y || true
create_cronjob_once "/etc/cron.daily/rkhunter" "#!/bin/bash
/usr/bin/rkhunter --check --sk --report-warnings-only
"
log "rkhunter installiert und konfiguriert."

# === SSH-Konfiguration: Passwortlogin erlaubt, kein Key-Zwang, Root-Login verboten ===
if [ -f /etc/ssh/sshd_config ]; then
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sshd -t && systemctl reload sshd
    log "SSH-Konfiguration: Passwort-Login erlaubt, Root-Login verboten."
fi

# === Zentrale System-Logs auf externen Syslog-Server schicken (optional auskommentieren) ===
# SYSLOG_SERVER="syslog.example.com"
# if ! grep -q "^*.* @$SYSLOG_SERVER" /etc/rsyslog.conf; then
#     echo "*.* @$SYSLOG_SERVER" >> /etc/rsyslog.conf
#     systemctl restart rsyslog
#     log "Zentrale System-Logs werden an $SYSLOG_SERVER weitergeleitet."
# fi

# === Unnötige Kernel-Module blockieren (Beispiel für selten benötigte Module) ===
cat <<EOF > /etc/modprobe.d/blacklist-custom.conf
# Unsichere oder nicht benötigte Kernel-Module blockieren
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
blacklist udf
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
EOF
log "Nicht benötigte Kernel-Module geblacklistet."

# === Autoremove nicht mehr benötigter Pakete ===
apt-get autoremove -y

# === Hinweis auf erforderlichen Reboot ===
REBOOT_NEEDED=0
if [ -f /var/run/reboot-required ]; then
    REBOOT_NEEDED=1
    log "Ein Neustart des Systems ist erforderlich, um alle Änderungen zu übernehmen."
fi

# === Systemprüfung nach Härtung ===
log "Starte Systemprüfungen nach Härtung..."

systemctl is-active fail2ban >/dev/null || log "Warnung: fail2ban läuft nicht!"
mount | grep /tmp >/dev/null || log "Warnung: /tmp ist nicht eingehängt!"
mount | grep /dev/shm >/dev/null || log "Warnung: /dev/shm ist nicht eingehängt!"
systemctl is-active auditd >/dev/null || log "Warnung: auditd läuft nicht!"
systemctl is-active apparmor >/dev/null || log "Warnung: AppArmor läuft nicht!"

# === Abschluss & Benachrichtigung ===
log "Sicherheitsmaßnahmen abgeschlossen. Bitte überprüfen Sie die Konfiguration und passen Sie ggf. weitere Einstellungen an."
if [ "$REBOOT_NEEDED" -eq 1 ]; then
    SUBJECT="Proxmox-Hardening abgeschlossen: Reboot empfohlen"
else
    SUBJECT="Proxmox-Hardening abgeschlossen"
fi
echo "Das Proxmox-Hardening-Skript (Version $SCRIPT_VERSION) wurde erfolgreich ausgeführt. Bitte prüfen Sie das Logfile ($LOGFILE) und führen Sie ggf. einen Neustart durch." | mail -s "$SUBJECT" "$EMAIL"
