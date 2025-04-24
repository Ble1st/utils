#!/bin/bash
set -e

# Variables
EMAIL="test"
HOME_NET="192.168.1.0/24"

# Funktion für das Auswahlmenü
function show_menu() {
    echo "========================================="
    echo " System Hardening Auswahlmenü"
    echo "========================================="
    echo "1) System aktualisieren und Pakete installieren"
    echo "2) Postfix konfigurieren (E-Mail-Benachrichtigungen)"
    echo "3) SSH-Härtung"
    echo "4) Fail2Ban konfigurieren"
    echo "5) Logwatch konfigurieren"
    echo "6) Sudo-Härtung"
    echo "7) Kernel-Härtung"
    echo "8) AppArmor konfigurieren"
    echo "9) Auditd konfigurieren"
    echo "10) AIDE konfigurieren"
    echo "11) Rootkit-Checker konfigurieren"
    echo "12) Nicht benötigte Dienste deaktivieren"
    echo "13) Chrony (NTP) konfigurieren"
    echo "14) NFS aktivieren"
    echo "15) ALLES AUSFÜHREN"
    echo "0) Beenden"
    echo "========================================="
}

# Funktion für die Auswahl
function execute_option() {
    case $1 in
        1)
            echo "1) System aktualisieren und Pakete installieren..."
            apt update && apt full-upgrade -y
            apt install -y fail2ban logwatch postfix sudo apparmor apparmor-utils auditd aide chkrootkit rkhunter chrony
            ;;
        2)
            echo "2) Postfix konfigurieren..."
            debconf-set-selections <<< "postfix postfix/mailname string $(hostname)"
            debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
            sed -i "s/^#mydestination = .*/mydestination = $(hostname), localhost/" /etc/postfix/main.cf
            systemctl enable postfix
            systemctl restart postfix
            ;;
        3)
            echo "3) SSH-Härtung..."
            sed -i 's/^#PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
            sed -i 's/^#PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
            sed -i 's/^#UsePAM .*/UsePAM yes/' /etc/ssh/sshd_config
            echo "AllowUsers $EMAIL" >> /etc/ssh/sshd_config
            systemctl restart sshd
            ;;
        4)
            echo "4) Fail2Ban konfigurieren..."
            cat <<EOL > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = $EMAIL
sender = fail2ban@$(hostname)
mta = sendmail

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
EOL
            systemctl enable --now fail2ban
            ;;
        5)
            echo "5) Logwatch konfigurieren..."
            logwatch_conf="/etc/cron.daily/00logwatch"
            sed -i "s/^MailTo = .*/MailTo = $EMAIL/" $logwatch_conf
            ;;
        6)
            echo "6) Sudo-Härtung..."
            cat <<EOL > /etc/sudoers.d/secure_sudo
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults env_reset, timestamp_timeout=0
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOL
            chmod 440 /etc/sudoers.d/secure_sudo
            ;;
        7)
            echo "7) Kernel-Härtung..."
            cat <<EOL > /etc/sysctl.d/99-hardening.conf
# Kernel Hardening
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
EOL
            sysctl --system
            ;;
        8)
            echo "8) AppArmor konfigurieren..."
            systemctl enable apparmor
            aa-enforce /etc/apparmor.d/*
            ;;
        9)
            echo "9) Auditd konfigurieren..."
            cat <<EOL > /etc/audit/audit.rules
# CIS and BSI Audit Rules
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /var/log/ -p wa -k log_changes
EOL
            systemctl restart auditd
            ;;
        10)
            echo "10) AIDE konfigurieren..."
            aideinit
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            echo "0 5 * * * root /usr/bin/aide.wrapper --check" >> /etc/crontab
            ;;
        11)
            echo "11) Rootkit-Checker konfigurieren..."
            chkrootkit
            rkhunter --update
            rkhunter --propupd
            echo "0 3 * * * root /usr/bin/chkrootkit" >> /etc/crontab
            echo "0 4 * * * root /usr/bin/rkhunter --checkall --report-warnings-only" >> /etc/crontab
            ;;
        12)
            echo "12) Nicht benötigte Dienste deaktivieren..."
            SERVICES=(
                "avahi-daemon" "cups" "bluetooth" "rpcbind"
                "vsftpd" "apache2" "bind9" "telnet" "xinetd" "dovecot"
            )
            for SERVICE in "${SERVICES[@]}"; do
                if systemctl is-active --quiet "$SERVICE"; then
                    systemctl stop "$SERVICE"
                    systemctl disable "$SERVICE"
                fi
            done
            ;;
        13)
            echo "13) Chrony (NTP) konfigurieren..."
            cat <<EOL > /etc/chrony/chrony.conf
pool 0.debian.pool.ntp.org iburst
pool 1.debian.pool.ntp.org iburst
pool 2.debian.pool.ntp.org iburst
pool 3.debian.pool.ntp.org iburst

allow $HOME_NET

log tracking measurements statistics
logdir /var/log/chrony
EOL
            systemctl enable chrony
            systemctl restart chrony
            ;;
        14)
            echo "14) NFS aktivieren..."
            systemctl enable nfs-common
            systemctl start nfs-common
            ;;
        15)
            echo "15) ALLES AUSFÜHREN..."
            for i in {1..14}; do
                execute_option $i
            done
            ;;
        0)
            echo "Beenden..."
            exit 0
            ;;
        *)
            echo "Ungültige Auswahl! Bitte erneut versuchen."
            ;;
    esac
}

# Hauptprogramm
while true; do
    show_menu
    read -p "Wählen Sie eine Option: " CHOICE
    execute_option $CHOICE
done
