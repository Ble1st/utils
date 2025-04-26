#!/bin/bash

# Überprüfen, ob das Skript mit sudo ausgeführt wird
if [ "$(id -u)" -ne 0 ]; then
    echo "Dieses Skript muss mit sudo ausgeführt werden. Bitte führen Sie es erneut mit 'sudo' aus."
    exit 1
fi

# Variablen (dynamisch anpassbar)
PROXMOX_USER="test" # Benutzername für Proxmox-Admin (dynamisch setzen)
DISABLE_SERVICES=("telnet") # Dienste, die deaktiviert werden sollen (Liste erweitern)
EMAIL="$PROXMOX_USER@localhost" # Ziel-E-Mail für Root-Mails

# MTA (Postfix) installieren und konfigurieren
echo "Installieren und Konfigurieren von Postfix..."
debconf-set-selections <<< "postfix postfix/mailname string $(hostname)"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Local only'"
apt-get install -y postfix
sed -i "s/^mydestination.*/mydestination = localhost/" /etc/postfix/main.cf
systemctl restart postfix

# Nicht benötigte Dienste deaktivieren
echo "Deaktivieren nicht benötigter Dienste..."
for service in "${DISABLE_SERVICES[@]}"; do
    systemctl disable --now "$service"
done

# Automatische Updates einrichten (Proxmox-Pakete auf Blacklist setzen)
echo "Einrichten automatischer Updates..."
apt-get install -y unattended-upgrades
echo "Proxmox-Pakete auf Blacklist setzen..."
cat <<EOF > /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
    "origin=Debian,codename=\${distro_codename},label=Debian-Security";
};
Unattended-Upgrade::Package-Blacklist {
    "proxmox-ve";
    "pve-kernel";
    "pve-manager";
};
EOF
dpkg-reconfigure -plow unattended-upgrades

# Mail-Weiterleitung für Root einrichten
echo "Weiterleitung von Root-Mails an $EMAIL einrichten..."
echo "root: $EMAIL" >> /etc/aliases
newaliases

# Logwatch einrichten
echo "Einrichten von Logwatch..."
apt-get install -y logwatch
cat <<EOF > /etc/cron.weekly/00logwatch
#!/bin/bash
/usr/sbin/logwatch --output mail --mailto $EMAIL --detail high
EOF
chmod +x /etc/cron.weekly/00logwatch

# Fail2ban installieren und konfigurieren (inkl. Proxmox)
echo "Installieren und Konfigurieren von Fail2ban..."
apt-get install -y fail2ban
cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 3
destemail = $EMAIL
sender = fail2ban@$HOSTNAME
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

# Fail2ban Filter für Proxmox hinzufügen
cat <<EOF > /etc/fail2ban/filter.d/proxmox.conf
[Definition]
failregex = .*authentication failure;.*user=<F-USER>.*
ignoreregex =
EOF

systemctl enable --now fail2ban

# AppArmor installieren und aktivieren
echo "Installieren und Aktivieren von AppArmor..."
apt-get install -y apparmor apparmor-profiles apparmor-utils
systemctl enable --now apparmor

# Kernel-Hardening nach BSI und NITS Empfehlungen
echo "Einrichten empfohlener Kernel-Parameter..."
cat <<EOF >> /etc/sysctl.conf
# Forwarding deaktivieren
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

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
net.ipv6.conf.all.disable_ipv6 = 1

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

sysctl -p

# Fstab-Hardening: /tmp und /dev/shm sichern
echo "Sichern von /tmp und /dev/shm..."
cat <<EOF >> /etc/fstab
tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0
tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0
EOF
mount -o remount /tmp
mount -o remount /dev/shm

# Auditd installieren und aktivieren
echo "Installieren und Aktivieren von Auditd..."
apt-get install -y auditd
systemctl enable --now auditd

# AIDE installieren und einrichten
echo "Installieren und Einrichten von AIDE..."
apt-get install -y aide
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
cat <<EOF > /etc/cron.daily/aide
#!/bin/bash
/usr/bin/aide.wrapper --check
EOF
chmod +x /etc/cron.daily/aide

# Rootkit Hunter (rkhunter) installieren und konfigurieren
echo "Installieren und Konfigurieren von rkhunter..."
apt-get install -y rkhunter
rkhunter --update
rkhunter --propupd
cat <<EOF > /etc/cron.daily/rkhunter
#!/bin/bash
/usr/bin/rkhunter --check --sk --report-warnings-only
EOF
chmod +x /etc/cron.daily/rkhunter

# SSH-Konfiguration (Passwortlogin erlauben, kein Key)
echo "Konfigurieren von SSH (nur Passwortlogin)..."
sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl reload sshd

# Abschluss
echo "Sicherheitsmaßnahmen abgeschlossen. Bitte überprüfen Sie die Konfiguration."
