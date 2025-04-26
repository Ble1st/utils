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

# === Schritt-Funktionen ===

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
    apt-get install -y postfix
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
}

schritt_mail_alias() {
    sed -i '/^root:/d' /etc/aliases
    add_unique_line "root: $EMAIL" /etc/aliases
    newaliases
    log "Mailweiterleitung für root eingerichtet."
}

schritt_logwatch() {
    apt-get install -y logwatch
    create_cronjob_once "/etc/cron.weekly/00logwatch" "#!/bin/bash
/usr/sbin/logwatch --output mail --mailto $EMAIL --detail high
"
}

schritt_fail2ban() {
    apt-get install -y fail2ban
    cat <<EOF > /etc/fail2ban/jail.local
#
# WARNING: heavily refactored in 0.9.0 release.  Please review and
#          customize settings for your setup.
#
# Changes:  in most of the cases you should not modify this
#           file, but provide customizations in jail.local file,
#           or separate .conf files under jail.d/ directory, e.g.:
#
# HOW TO ACTIVATE JAILS:
#
# YOU SHOULD NOT MODIFY THIS FILE.
#
# It will probably be overwritten or improved in a distribution update.
#
# Provide customizations in a jail.local file or a jail.d/customisation.local.
# For example to change the default bantime for all jails and to enable the
# ssh-iptables jail the following (uncommented) would appear in the .local file.
# See man 5 jail.conf for details.
#
# [DEFAULT]
# bantime = 1h
#
# [sshd]
# enabled = true
#
# See jail.conf(5) man page for more information



# Comments: use '#' for comment lines and ';' (following a space) for inline comments


[INCLUDES]

#before = paths-distro.conf
before = paths-debian.conf

# The DEFAULT allows a global definition of the options. They can be overridden
# in each jail afterwards.

[DEFAULT]

#
# MISCELLANEOUS OPTIONS
#

# "bantime.increment" allows to use database for searching of previously banned ip's to increase a 
# default ban time using special formula, default it is banTime * 1, 2, 4, 8, 16, 32...
#bantime.increment = true

# "bantime.rndtime" is the max number of seconds using for mixing with random time 
# to prevent "clever" botnets calculate exact time IP can be unbanned again:
#bantime.rndtime = 

# "bantime.maxtime" is the max number of seconds using the ban time can reach (doesn't grow further)
#bantime.maxtime = 

# "bantime.factor" is a coefficient to calculate exponent growing of the formula or common multiplier,
# default value of factor is 1 and with default value of formula, the ban time 
# grows by 1, 2, 4, 8, 16 ...
#bantime.factor = 1

# "bantime.formula" used by default to calculate next value of ban time, default value below,
# the same ban time growing will be reached by multipliers 1, 2, 4, 8, 16, 32...
#bantime.formula = ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor
#
# more aggressive example of formula has the same values only for factor "2.0 / 2.885385" :
#bantime.formula = ban.Time * math.exp(float(ban.Count+1)*banFactor)/math.exp(1*banFactor)

# "bantime.multipliers" used to calculate next value of ban time instead of formula, corresponding
# previously ban count and given "bantime.factor" (for multipliers default is 1);
# following example grows ban time by 1, 2, 4, 8, 16 ... and if last ban count greater as multipliers count, 
# always used last multiplier (64 in example), for factor '1' and original ban time 600 - 10.6 hours
#bantime.multipliers = 1 2 4 8 16 32 64
# following example can be used for small initial ban time (bantime=60) - it grows more aggressive at begin,
# for bantime=60 the multipliers are minutes and equal: 1 min, 5 min, 30 min, 1 hour, 5 hour, 12 hour, 1 day, 2 day
#bantime.multipliers = 1 5 30 60 300 720 1440 2880

# "bantime.overalljails" (if true) specifies the search of IP in the database will be executed 
# cross over all jails, if false (default), only current jail of the ban IP will be searched
#bantime.overalljails = false

# --------------------

# "ignoreself" specifies whether the local resp. own IP addresses should be ignored
# (default is true). Fail2ban will not ban a host which matches such addresses.
#ignoreself = true

# "ignoreip" can be a list of IP addresses, CIDR masks or DNS hosts. Fail2ban
# will not ban a host which matches an address in this list. Several addresses
# can be defined using space (and/or comma) separator.
#ignoreip = 127.0.0.1/8 ::1

# External command that will take an tagged arguments to ignore, e.g. <ip>,
# and return true if the IP is to be ignored. False otherwise.
#
# ignorecommand = /path/to/command <ip>
ignorecommand =

# "bantime" is the number of seconds that a host is banned.
bantime  = 10m

# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime  = 10m

# "maxretry" is the number of failures before a host get banned.
maxretry = 3

# "maxmatches" is the number of matches stored in ticket (resolvable via tag <matches> in actions).
maxmatches = %(maxretry)s

# "backend" specifies the backend used to get files modification.
# Available options are "pyinotify", "gamin", "polling", "systemd" and "auto".
# This option can be overridden in each jail as well.
#
# pyinotify: requires pyinotify (a file alteration monitor) to be installed.
#              If pyinotify is not installed, Fail2ban will use auto.
# gamin:     requires Gamin (a file alteration monitor) to be installed.
#              If Gamin is not installed, Fail2ban will use auto.
# polling:   uses a polling algorithm which does not require external libraries.
# systemd:   uses systemd python library to access the systemd journal.
#              Specifying "logpath" is not valid for this backend.
#              See "journalmatch" in the jails associated filter config
# auto:      will try to use the following backends, in order:
#              pyinotify, gamin, polling.
#
# Note: if systemd backend is chosen as the default but you enable a jail
#       for which logs are present only in its own log files, specify some other
#       backend for that jail (e.g. polling) and provide empty value for
#       journalmatch. See https://github.com/fail2ban/fail2ban/issues/959#issuecomment-74901200
backend = auto

# "usedns" specifies if jails should trust hostnames in logs,
#   warn when DNS lookups are performed, or ignore all hostnames in logs
#
# yes:   if a hostname is encountered, a DNS lookup will be performed.
# warn:  if a hostname is encountered, a DNS lookup will be performed,
#        but it will be logged as a warning.
# no:    if a hostname is encountered, will not be used for banning,
#        but it will be logged as info.
# raw:   use raw value (no hostname), allow use it for no-host filters/actions (example user)
usedns = warn

# "logencoding" specifies the encoding of the log files handled by the jail
#   This is used to decode the lines from the log file.
#   Typical examples:  "ascii", "utf-8"
#
#   auto:   will use the system locale setting
logencoding = auto

# "enabled" enables the jails.
#  By default all jails are disabled, and it should stay this way.
#  Enable only relevant to your setup jails in your .local or jail.d/*.conf
#
# true:  jail will be enabled and log files will get monitored for changes
# false: jail is not enabled
enabled = false


# "mode" defines the mode of the filter (see corresponding filter implementation for more info).
mode = normal

# "filter" defines the filter to use by the jail.
#  By default jails have names matching their filter name
#
filter = %(__name__)s[mode=%(mode)s]


#
# ACTIONS
#

# Some options used for actions

# Destination email address used solely for the interpolations in
# jail.{conf,local,d/*} configuration files.
destemail = gerd@big

# Sender email address used solely for some actions
sender = root@big

# E-mail action. Since 0.8.1 Fail2Ban uses sendmail MTA for the
# mailing. Change mta configuration parameter to mail if you want to
# revert to conventional 'mail'.
mta = sendmail

# Default protocol
protocol = tcp

# Specify chain where jumps would need to be added in ban-actions expecting parameter chain
chain = <known/chain>

# Ports to be banned
# Usually should be overridden in a particular jail
port = 0:65535

# Format of user-agent https://tools.ietf.org/html/rfc7231#section-5.5.3
fail2ban_agent = Fail2Ban/%(fail2ban_version)s

#
# Action shortcuts. To be used to define action parameter

# Default banning action (e.g. iptables, iptables-new,
# iptables-multiport, shorewall, etc) It is used to define
# action_* variables. Can be overridden globally or per
# section within jail.local file
banaction = iptables-multiport
banaction_allports = iptables-allports

# The simplest action to take: ban only
action_ = %(banaction)s[port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]

# ban & send an e-mail with whois report to the destemail.
action_mw = %(action_)s
            %(mta)s-whois[sender="%(sender)s", dest="%(destemail)s", protocol="%(protocol)s", chain="%(chain)s"]

# ban & send an e-mail with whois report and relevant log lines
# to the destemail.
action_mwl = %(action_)s
             %(mta)s-whois-lines[sender="%(sender)s", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]

# See the IMPORTANT note in action.d/xarf-login-attack for when to use this action
#
# ban & send a xarf e-mail to abuse contact of IP address and include relevant log lines
# to the destemail.
action_xarf = %(action_)s
             xarf-login-attack[service=%(__name__)s, sender="%(sender)s", logpath="%(logpath)s", port="%(port)s"]

# ban & send a notification to one or more of the 50+ services supported by Apprise.
# See https://github.com/caronc/apprise/wiki for details on what is supported.
#
# You may optionally over-ride the default configuration line (containing the Apprise URLs)
# by using 'apprise[config="/alternate/path/to/apprise.cfg"]' otherwise
# /etc/fail2ban/apprise.conf is sourced for your supported notification configuration.
# action = %(action_)s
#          apprise

# ban IP on CloudFlare & send an e-mail with whois report and relevant log lines
# to the destemail.
action_cf_mwl = cloudflare[cfuser="%(cfemail)s", cftoken="%(cfapikey)s"]
                %(mta)s-whois-lines[sender="%(sender)s", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]

# Report block via blocklist.de fail2ban reporting service API
# 
# See the IMPORTANT note in action.d/blocklist_de.conf for when to use this action.
# Specify expected parameters in file action.d/blocklist_de.local or if the interpolation
# `action_blocklist_de` used for the action, set value of `blocklist_de_apikey`
# in your `jail.local` globally (section [DEFAULT]) or per specific jail section (resp. in 
# corresponding jail.d/my-jail.local file).
#
action_blocklist_de  = blocklist_de[email="%(sender)s", service="%(__name__)s", apikey="%(blocklist_de_apikey)s", agent="%(fail2ban_agent)s"]

# Report ban via abuseipdb.com.
#
# See action.d/abuseipdb.conf for usage example and details.
#
action_abuseipdb = abuseipdb

# Choose default action.  To change, just override value of 'action' with the
# interpolation to the chosen action shortcut (e.g.  action_mw, action_mwl, etc) in jail.local
# globally (section [DEFAULT]) or per specific section
action = %(action_)s


#
# JAILS
#

#
# SSH servers
#


# To use more aggressive sshd modes set filter parameter "mode" in jail.local:
# normal (default), ddos, extra or aggressive (combines all).
# See "tests/files/logs/sshd" or "filter.d/sshd.conf" for usage example and details.
#mode   = normal
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

failregex = ^.*pam_unix\(proxmox-ve-auth:auth\): authentication failure; .* rhost=<HOST> .*$

            ^.*pvedaemon\[.*\]: authentication failure; rhost=<HOST> .*$

ignoreregex =

EOF

    systemctl enable --now fail2ban
    log "Fail2ban installiert und konfiguriert."
}

schritt_apparmor() {
    apt-get install -y apparmor apparmor-profiles apparmor-utils
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
}

schritt_auditd() {
    apt-get install -y auditd
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
    apt-get install -y aide

    # Proxmox-relevante Pfade zur aide.conf hinzufügen, falls nicht vorhanden
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
/usr/bin/aide.wrapper --check
"
    log "AIDE installiert und Proxmox-Konfiguration integriert."
}

schritt_rkhunter() {
    apt-get install -y rkhunter
    rkhunter --update || true
    rkhunter --propupd -y || true
    create_cronjob_once "/etc/cron.daily/rkhunter" "#!/bin/bash
/usr/bin/rkhunter --check --sk --report-warnings-only
"
    log "rkhunter installiert und konfiguriert."
}

schritt_ssh_config() {
    if [ -f /etc/ssh/sshd_config ]; then
        sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sshd -t && systemctl reload sshd
        log "SSH-Konfiguration: Passwort-Login erlaubt, Root-Login verboten."
    fi
}

schritt_blacklist_modules() {
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
    if [ "$reboot_needed" -eq 1 ]; then
        SUBJECT="Proxmox-Hardening abgeschlossen: Reboot empfohlen"
    else
        SUBJECT="Proxmox-Hardening abgeschlossen"
    fi
    echo "Das Proxmox-Hardening-Skript (Version $SCRIPT_VERSION) wurde erfolgreich ausgeführt. Bitte prüfen Sie das Logfile ($LOGFILE) und führen Sie ggf. einen Neustart durch." | mail -s "$SUBJECT" "$EMAIL"
}

# === Menü ===

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
    echo "17) Autoremove nicht mehr benötigter Pakete"
    echo "18) Systemprüfung nach Härtung"
    echo "19) Alle Schritte ausführen"
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
            17) schritt_autoremove ;;
            18) schritt_systemchecks ;;
            19)
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
        read -rp "Ihre Auswahl (z.B. 1 3 5 oder 19 für alles): " -a selected_steps
        if [[ " ${selected_steps[@]} " =~ " 0 " ]]; then
            echo "Beende..."
            exit 0
        fi
        if [[ " ${selected_steps[@]} " =~ " 19 " ]]; then
            selected_steps=(19)
        fi
        run_selected_steps
        echo "Fertig. Das Menü wird erneut angezeigt."
    done
}

main
