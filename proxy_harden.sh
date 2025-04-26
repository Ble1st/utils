#!/bin/bash
set -euo pipefail

SCRIPT_VERSION="1.5"
LOGFILE="/var/log/proxmox_hardening.log"

# === Konfigurierbare Variablen ===
PROXMOX_USER="test" # Proxmox-Admin-Benutzer
EMAIL="$PROXMOX_USER@localhost"
DISABLE_SERVICES=("telnet") # Zu deaktivierende Dienste (erweiterbar)
BLACKLIST_MODULES=(
    "cramfs"
    "freevxfs"
    "jffs2"
    "hfs"
    "hfsplus"
    "squashfs"
    "udf"
    "dccp"
    "sctp"
    "rds"
    "tipc"
    "kexec"
)

log() {
    local msg="$1"
    echo "$(date '+%F %T') [$SCRIPT_VERSION] $msg" | tee -a "$LOGFILE" >&2
    logger -t proxmox_hardening "$msg"
}

backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        local ts
        ts="$(date +%F-%H%M%S)"
        cp "$file" "${file}.bak.${ts}.$(hostname)"
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

check_command() {
    command -v "$1" >/dev/null 2>&1
}

if [ "$(id -u)" -ne 0 ]; then
    log "Dieses Skript muss als root ausgeführt werden (z.B. mit sudo)."
    exit 1
fi

schritt_proxmox_check() {
    log "Starte Proxmox-Hardening-Skript Version $SCRIPT_VERSION."
    if [ ! -d /etc/pve ]; then
        log "Warnung: Proxmox scheint auf diesem System nicht installiert zu sein (/etc/pve fehlt)."
    fi
}

schritt_backup_configs() {
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
}

schritt_postfix() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y postfix || { log "Fehler: postfix konnte nicht installiert werden!"; exit 1; }
    log "Postfix installiert."
}

schritt_disable_services() {
    for service in "${DISABLE_SERVICES[@]}"; do
        if systemctl list-unit-files | grep -qw "$service"; then
            systemctl disable --now "$service"
            log "Dienst $service deaktiviert."
        fi
    done
}

schritt_unattended_upgrades() {
    apt-get install -y unattended-upgrades || { log "Fehler: unattended-upgrades konnte nicht installiert werden!"; exit 1; }
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
}

schritt_mail_alias() {
    sed -i '/^root:/d' /etc/aliases
    add_unique_line "root: $EMAIL" /etc/aliases
    newaliases
    log "Mailweiterleitung für root eingerichtet."
}

schritt_logwatch() {
    apt-get install -y logwatch || { log "Fehler: logwatch konnte nicht installiert werden!"; exit 1; }
    create_cronjob_once "/etc/cron.weekly/00logwatch" "#!/bin/bash
if [ -x /usr/sbin/logwatch ]; then
    /usr/sbin/logwatch --output mail --mailto $EMAIL --detail high
fi
"
}

schritt_fail2ban() {
    apt-get install -y fail2ban || { log "Fehler: fail2ban konnte nicht installiert werden!"; exit 1; }
    cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime  = 10m
findtime  = 10m
maxretry = 3
usedns = warn
logencoding = auto
enabled = false
mode = normal
filter = %(__name__)s[mode=%(mode)s]
destemail = $EMAIL
sender = root@localhost
mta = sendmail
protocol = tcp
chain = <known/chain>
port = 0:65535
fail2ban_agent = Fail2Ban/%(fail2ban_version)s
banaction = iptables-multiport
banaction_allports = iptables-allports
action = %(banaction)s[port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]

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
backend = systemd
maxretry = 3
bantime = 600
findtime = 600
EOF

    cat <<EOF > /etc/fail2ban/filter.d/proxmox.conf
[Definition]
failregex = ^.*pam_unix\(proxmox-ve-auth:auth\): authentication failure; .* rhost=<HOST> .*\$
            ^.*pvedaemon\[.*\]: authentication failure; rhost=<HOST> .*\$
ignoreregex =
EOF

    systemctl enable --now fail2ban
    log "Fail2ban installiert und konfiguriert."
}

schritt_apparmor() {
    apt-get install -y apparmor apparmor-profiles apparmor-utils || { log "Fehler: AppArmor konnte nicht installiert werden!"; exit 1; }
    if lsmod | grep -q apparmor; then
        systemctl enable --now apparmor
        log "AppArmor aktiviert."
    fi
}

schritt_sysctl_hardening() {
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

    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1
    log "Cluster-Konfiguration: IPv4 und IPv6 Forwarding aktiviert (sofort und persistent)."
    sysctl --system
}

schritt_fstab_hardening() {
    safe_add_to_fstab "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" "/tmp"
    safe_add_to_fstab "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" "/dev/shm"
    mount -o remount /tmp || true
    mount -o remount /dev/shm || true

    for mountpoint in /tmp /dev/shm; do
        mount | grep "$mountpoint" | grep -q "noexec" || log "Warnung: $mountpoint ohne noexec gemountet!"
        mount | grep "$mountpoint" | grep -q "nosuid" || log "Warnung: $mountpoint ohne nosuid gemountet!"
        mount | grep "$mountpoint" | grep -q "nodev" || log "Warnung: $mountpoint ohne nodev gemountet!"
    done
}

schritt_auditd() {
    apt-get install -y auditd || { log "Fehler: auditd konnte nicht installiert werden!"; exit 1; }
    systemctl enable --now auditd
    log "Auditd installiert und aktiviert."
    cat <<EOF > /etc/audit/rules.d/proxmox-critical.rules
-w /etc/pve/ -p wa -k proxmox_conf_change
-w /etc/passwd -p wa -k passwd_change
-w /etc/shadow -p wa -k shadow_change
-w /etc/ssh/sshd_config -p wa -k sshd_config_change
-w /etc/network/interfaces -p wa -k netif_change
EOF
    augenrules --load
    log "Auditd-Regeln für kritische Dateien eingerichtet."
}

schritt_aide() {
    apt-get install -y aide || { log "Fehler: aide konnte nicht installiert werden!"; exit 1; }
    aide_conf="/etc/aide/aide.conf"
    grep -q "/etc/pve/" "$aide_conf" || cat <<EOF >> "$aide_conf"

# Proxmox relevante Verzeichnisse und Dateien
/etc/pve/          NORMAL
/etc/lvm/          NORMAL
/etc/network/      NORMAL
/etc/ssh/          NORMAL
/etc/cron.d/       NORMAL
/etc/cron.daily/   NORMAL
/etc/cron.weekly/  NORMAL
/etc/postfix/      NORMAL
EOF

    aideinit || true
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db || true
    create_cronjob_once "/etc/cron.daily/aide" "#!/bin/bash
if [ -x /usr/bin/aide.wrapper ]; then
    /usr/bin/aide.wrapper --check
fi
"
    log "AIDE installiert und Proxmox-Konfiguration integriert."
}

schritt_rkhunter() {
    apt-get install -y rkhunter || { log "Fehler: rkhunter konnte nicht installiert werden!"; exit 1; }
    rkhunter --update || true
    rkhunter --propupd -y || true
    create_cronjob_once "/etc/cron.daily/rkhunter" "#!/bin/bash
if [ -x /usr/bin/rkhunter ]; then
    /usr/bin/rkhunter --check --sk --report-warnings-only
fi
"
    log "rkhunter installiert und konfiguriert."
}

schritt_ssh_config() {
    if [ -f /etc/ssh/sshd_config ]; then
        backup_file /etc/ssh/sshd_config
        # Passwort-Login weiterhin erlaubt, Root-Login verboten
        sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

        if sshd -t; then
            systemctl reload sshd
            log "SSH-Konfiguration: Passwort-Login erlaubt, Root-Login verboten."
        else
            log "Fehler in der SSH-Konfiguration!"
        fi
    fi
}

schritt_blacklist_modules() {
    local conf_file="/etc/modprobe.d/blacklist-custom.conf"
    echo "# Unsichere oder nicht benötigte Kernel-Module blockieren" > "$conf_file"
    for mod in "${BLACKLIST_MODULES[@]}"; do
        echo "blacklist $mod" >> "$conf_file"
    done
    log "Nicht benötigte Kernel-Module geblacklistet."
}

schritt_kexec_tools() {
    apt-get install -y kexec-tools || { log "Fehler: kexec-tools konnte nicht installiert werden!"; exit 1; }
    log "kexec-tools installiert. Ermöglicht schnellen Kernel-Neustart nach automatischen Kernel-Updates."
}

schritt_autoremove() {
    apt-get autoremove -y
}

schritt_reboot_hint() {
    REBOOT_NEEDED=0
    if [ -f /var/run/reboot-required ]; then
        REBOOT_NEEDED=1
        log "Ein Neustart des Systems ist erforderlich, um alle Änderungen zu übernehmen."
    fi
    return $REBOOT_NEEDED
}

schritt_systemchecks() {
    log "Starte Systemprüfungen nach Härtung..."
    systemctl is-active fail2ban >/dev/null || log "Warnung: fail2ban läuft nicht!"
    mount | grep /tmp >/dev/null || log "Warnung: /tmp ist nicht eingehängt!"
    mount | grep /dev/shm >/dev/null || log "Warnung: /dev/shm ist nicht eingehängt!"
    systemctl is-active auditd >/dev/null || log "Warnung: auditd läuft nicht!"
    systemctl is-active apparmor >/dev/null || log "Warnung: AppArmor läuft nicht!"
}

schritt_final_message() {
    local reboot_needed=$1
    log "Sicherheitsmaßnahmen abgeschlossen. Bitte überprüfen Sie die Konfiguration und passen Sie ggf. weitere Einstellungen an."
    local SUBJECT
    if [ "$reboot_needed" -eq 1 ]; then
        SUBJECT="Proxmox-Hardening abgeschlossen: Reboot empfohlen"
    else
        SUBJECT="Proxmox-Hardening abgeschlossen"
    fi
    if check_command mail; then
        echo "Das Proxmox-Hardening-Skript (Version $SCRIPT_VERSION) wurde erfolgreich ausgeführt. Bitte prüfen Sie das Logfile ($LOGFILE) und führen Sie ggf. einen Neustart durch." | mail -s "$SUBJECT" "$EMAIL"
    fi
}

show_menu() {
    echo "===== Proxmox Hardening: Auswahlmenü ====="
    echo "Bitte wählen Sie die gewünschten Schritte aus:"
    echo "1) Proxmox-Check"
    echo "2) Backup wichtiger Konfigurationsdateien"
    echo "3) Postfix installieren & konfigurieren"
    echo "4) Nicht benötigte Dienste deaktivieren"
    echo "5) Automatische Updates (unattended-upgrades)"
    echo "6) Mailweiterleitung für root"
    echo "7) Logwatch einrichten"
    echo "8) Fail2ban installieren & konfigurieren"
    echo "9) AppArmor installieren & aktivieren"
    echo "10) Kernel-Hardening (sysctl)"
    echo "11) Fstab-Hardening (/tmp und /dev/shm sichern)"
    echo "12) Auditd installieren & konfigurieren"
    echo "13) AIDE installieren & einrichten"
    echo "14) Rootkit Hunter installieren"
    echo "15) SSH-Konfiguration anpassen"
    echo "16) Kernel-Module blacklisten"
    echo "17) kexec-tools installieren (Kernel Live-Reboot Support)"
    echo "18) Autoremove nicht mehr benötigter Pakete"
    echo "19) Systemprüfung nach Härtung"
    echo "20) Alle Schritte ausführen"
    echo "0) Beenden"
    echo "=========================================="
}

run_selected_steps() {
    local reboot_needed=0
    for step in "${selected_steps[@]}"; do
        case $step in
            1) schritt_proxmox_check ;;
            2) schritt_backup_configs ;;
            3) schritt_postfix ;;
            4) schritt_disable_services ;;
            5) schritt_unattended_upgrades ;;
            6) schritt_mail_alias ;;
            7) schritt_logwatch ;;
            8) schritt_fail2ban ;;
            9) schritt_apparmor ;;
            10) schritt_sysctl_hardening ;;
            11) schritt_fstab_hardening ;;
            12) schritt_auditd ;;
            13) schritt_aide ;;
            14) schritt_rkhunter ;;
            15) schritt_ssh_config ;;
            16) schritt_blacklist_modules ;;
            17) schritt_kexec_tools ;;
            18) schritt_autoremove ;;
            19) schritt_systemchecks ;;
            20)
                schritt_proxmox_check
                schritt_backup_configs
                schritt_postfix
                schritt_disable_services
                schritt_unattended_upgrades
                schritt_mail_alias
                schritt_logwatch
                schritt_fail2ban
                schritt_apparmor
                schritt_sysctl_hardening
                schritt_fstab_hardening
                schritt_auditd
                schritt_aide
                schritt_rkhunter
                schritt_ssh_config
                schritt_blacklist_modules
                schritt_kexec_tools
                schritt_autoremove
                schritt_systemchecks
                ;;
        esac
    done

    schritt_reboot_hint
    reboot_needed=$?
    schritt_final_message "$reboot_needed"
}

main() {
    while true; do
        show_menu
        read -rp "Ihre Auswahl (z.B. 1 3 5 oder 20 für alles): " -a selected_steps
        if [[ " ${selected_steps[@]} " =~ " 0 " ]]; then
            echo "Beende..."
            exit 0
        fi
        if [[ " ${selected_steps[@]} " =~ " 20 " ]]; then
            selected_steps=(20)
        fi
        run_selected_steps
        echo "Fertig. Das Menü wird erneut angezeigt."
    done
}

main "$@"
