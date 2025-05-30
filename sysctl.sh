#!/bin/bash

# Interaktives Skript zur Kernel-Härtung für generische Linux-Server
# mit optionalen spezifischen Einstellungen für Docker oder Proxmox (VE/BK).
# JEDER Parameter ist kommentiert, damit klar ist, was er bewirkt.

set -e

OUTFILE="/etc/sysctl.d/90-linux-hardened.conf"
TMPFILE="$(mktemp)"

# Standard-Parameter (generisch & restriktiv), alle mit Kommentaren
cat > "$TMPFILE" << 'EOF'
# === Kernel-Härtung für generische Linux-Server ===

# --- Netzwerk Hardening ---

net.ipv4.ip_forward = 0                    # IPv4-Routing deaktivieren (keine Pakete weiterleiten)
net.ipv6.conf.all.forwarding = 0           # IPv6-Routing deaktivieren (keine Pakete weiterleiten)
net.ipv4.conf.all.send_redirects = 0       # ICMP Redirects (Routen-Umleitungen) auf allen Interfaces verbieten
net.ipv4.conf.default.send_redirects = 0   # ICMP Redirects auf neuen Interfaces verbieten
net.ipv4.conf.all.accept_source_route = 0  # Source Routing (Angreifer kann Pfad vorgeben) deaktivieren (IPv4)
net.ipv4.conf.default.accept_source_route = 0 # Source Routing auf neuen Interfaces deaktivieren (IPv4)
net.ipv6.conf.all.accept_source_route = 0  # Source Routing für IPv6 deaktivieren
net.ipv6.conf.default.accept_source_route = 0 # Source Routing für neue IPv6-Interfaces deaktivieren
net.ipv4.conf.all.accept_redirects = 0     # ICMP Redirects (Routen-Umleitungen) für IPv4 verbieten
net.ipv4.conf.default.accept_redirects = 0 # ICMP Redirects für neue IPv4-Interfaces verbieten
net.ipv6.conf.all.accept_redirects = 0     # ICMP Redirects (Routen-Umleitungen) für IPv6 verbieten
net.ipv6.conf.default.accept_redirects = 0 # ICMP Redirects für neue IPv6-Interfaces verbieten
net.ipv4.conf.all.secure_redirects = 0     # Sichere ICMP Redirects für IPv4 deaktivieren
net.ipv4.conf.default.secure_redirects = 0 # Sichere ICMP Redirects für neue IPv4-Interfaces deaktivieren
net.ipv4.conf.all.log_martians = 1         # "Martian"-Pakete (ungültig/verdächtig) loggen (IPv4)
net.ipv4.conf.default.log_martians = 1     # "Martian"-Pakete auf neuen Interfaces loggen (IPv4)
net.ipv4.icmp_echo_ignore_broadcasts = 1   # ICMP Echo (Ping) auf Broadcast-Adressen ignorieren
net.ipv4.icmp_ignore_bogus_error_responses = 1 # Falsche ICMP-Fehlermeldungen ignorieren
net.ipv4.conf.all.rp_filter = 1            # Reverse Path Filtering aktivieren (gegen IP-Spoofing, IPv4)
net.ipv4.conf.default.rp_filter = 1        # Reverse Path Filtering für neue Interfaces aktivieren (IPv4)
net.ipv4.tcp_syncookies = 1                # SYN Cookies aktivieren (Schutz gegen SYN-Flood-Angriffe)
net.ipv6.conf.all.accept_ra = 0            # IPv6: Router Advertisements ignorieren
net.ipv6.conf.default.accept_ra = 0        # IPv6: Router Advertisements auf neuen Interfaces ignorieren
net.ipv6.conf.all.disable_ipv6 = 1         # IPv6 auf allen Interfaces deaktivieren (falls nicht genutzt)
net.ipv6.conf.default.disable_ipv6 = 1     # IPv6 auf neuen Interfaces deaktivieren

# --- SYN-Flood und TCP Hardening ---

net.ipv4.tcp_max_syn_backlog = 4096        # Erhöht die Warteschlange für neue Verbindungen (Schutz gegen SYN-Flood)
net.ipv4.tcp_synack_retries = 2            # Reduziert die Wiederholungen für SYN/ACK (schnellere Freigabe von Ressourcen)
net.ipv4.tcp_max_orphans = 16384           # Maximale Anzahl an "verwaisten" TCP-Verbindungen
net.ipv4.tcp_rfc1337 = 1                   # Schutz gegen TIME-WAIT-Angriffe (RFC 1337)
net.ipv4.tcp_timestamps = 0                # TCP-Timestamps deaktivieren (erschwert Fingerprinting & Angriffe)
net.ipv4.tcp_sack = 0                      # TCP SACK (Selective ACK) deaktivieren (gegen bestimmte Angriffe, ggf. Performanceverlust)
net.ipv4.tcp_fack = 0                      # TCP FACK deaktivieren (zusammen mit sack, siehe oben)

# --- IP-Fragmentierungsangriffe erschweren ---

net.ipv4.ipfrag_high_thresh = 262144       # Obergrenze für zwischengespeicherte IP-Fragmentierung (in Bytes)
net.ipv4.ipfrag_low_thresh = 196608        # Untergrenze für Freigabe von Fragmenten (in Bytes)
net.ipv4.ipfrag_time = 30                  # Aufbewahrungszeit für Fragmente (Sekunden)

# --- Speicher- & Memory Protection ---

kernel.kptr_restrict = 2                   # Kernel-Pointer niemals für unpriv. User anzeigen (keine Infoleaks via /proc)
kernel.dmesg_restrict = 1                  # Zugriff auf dmesg auf root beschränken (keine Kernel-Infos für User)
kernel.yama.ptrace_scope = 2               # ptrace (Debugger) nur auf eigene Prozesse erlauben (erschwert Exploits)
kernel.randomize_va_space = 2              # Volle Adressraum-Layout-Randomisierung (ASLR)
vm.mmap_min_addr = 65536                   # Minimale virtuelle Adresse für mmap (verhindert NULL-Pointer-Dereferenz)
fs.protected_symlinks = 1                  # Schutz vor Symlink-Angriffen (privilege escalation)
fs.protected_hardlinks = 1                 # Schutz vor Hardlink-Angriffen (privilege escalation)
fs.protected_fifos = 1                     # Schutz vor Angriffen mit FIFOs (named pipes)
fs.protected_regular = 1                   # Schutz vor Angriffen mit regulären Dateien bei SUID/SGID
fs.suid_dumpable = 0                       # Keine Speicherabbilder (core dumps) bei SUID-Programmen (verhindert Infoleaks)

# --- Zusätzliche Kernel-Härtung ---

kernel.unprivileged_bpf_disabled = 1       # Unpriv. User dürfen kein eBPF verwenden (erschwert Exploits)
kernel.kexec_load_disabled = 1             # Kein Laden neuer Kernel-Images zur Laufzeit (erschwert Rootkits)
kernel.unprivileged_userns_clone = 0       # Unpriv. User dürfen keine User-Namespaces anlegen (erschwert Escapes)
kernel.perf_event_paranoid = 3             # Performance Counter nur root, keine Infos für User (Seitenkanalangriffe)
net.core.bpf_jit_harden = 2                # Verschärft eBPF JIT (erschwert Angriffe auf JIT)
kernel.sysrq = 4                           # Nur Magic SysRq reboot erlaubt (Schutz vor Missbrauch)
vm.panic_on_oom = 1                        # Kernel-Panic bei OOM (optional, verhindert Rootkits bei OOM)
kernel.panic = 10                          # Nach Kernel-Panic 10 Sekunden warten und dann rebooten
kernel.panic_on_oops = 1                   # Bei Kernel-Oops ebenfalls sofort rebooten (Schutz vor Angriffen)
kernel.printk = 4 4 1 7                    # Kernel-Logging restriktiv (weniger Infos für Angreifer)

# --- User namespaces ---

user.max_user_namespaces = 15000           # Maximale User-Namespaces (erlaubt ggf. für bestimmte Anwendungen, sonst verringern!)

# --- Memory Tagging Extension (nur ARMv8.5+ mit passendem Kernel, sonst ignoriert) ---
# kernel.arm64.tagged_addr_ctrl = 1       # Memory Tagging Extension aktivieren
# kernel.arm64.untag_mask = 0             # Maskiert keine Tags

# --- Zusätzliche Härtungsempfehlungen ---

fs.protected_tmpfs = 1                     # Schutz vor Symlink-Angriffen im tmpfs (/tmp auf tmpfs gemountet)
kernel.kstack_depth_to_print = 0           # Kernel Stacktraces werden nicht ausgegeben (gegen Infoleaks)
kernel.ftrace_enabled = 0                  # Kernel Tracing für unpriv. User deaktivieren (gegen Infoleaks)
kernel.sched_autogroup_enabled = 0         # Automatische Prozessgruppierung ausschalten (Side-Channel und Predictability)
vm.oom_dump_tasks = 1                      # OOM-Killer loggt alle Prozesse (hilft bei Debugging, kein direkter Security-Gewinn)

# --- Ergänzungen aus madduci-Gist ---

kernel.core_uses_pid = 1                   # Corefiles enthalten die PID (hilft Forensik)
kernel.core_pattern = /tmp/core.%e.%p.%h.%t # Corefiles in /tmp: Name, PID, Host und Zeit (Forensik, kein Security-Risiko)
kernel.ctrl-alt-del = 0                    # Ctrl+Alt+Del Reboot abschalten (Schutz vor versehentlichem/unerlaubtem Reboot)
EOF

# Menü
echo "Welche Software ist auf diesem System installiert?"
echo "1) Nichts davon (nur generische Linux-Härtung)"
echo "2) Docker"
echo "3) Proxmox Virtual Environment (PVE)"
echo "4) Proxmox Backup Server (PBS)"
echo "Mehrfachauswahl ist möglich (z.B. 2 3):"
read -rp "Bitte Auswahl eingeben: " auswahl

# Spaces entfernen und in Array aufteilen
read -ra auswahl_arr <<< "$auswahl"

for option in "${auswahl_arr[@]}"; do
  case $option in
    2)
      # Docker: IP-Forwarding und User-Namespaces für Container
      cat >> "$TMPFILE" << 'EOF'

# === Zusätzliche Parameter für Docker ===
net.ipv4.ip_forward = 1            # Für Container-Netzwerke: IPv4-Forwarding aktivieren
user.max_user_namespaces = 15000   # User-Namespaces für Container erlauben
# net.ipv6.conf.all.forwarding = 1 # Optional: IPv6-Forwarding aktivieren
EOF
      ;;
    3)
      # Proxmox VE: IP-Forwarding und User-Namespaces für LXC, Netzwerkbrücken
      cat >> "$TMPFILE" << 'EOF'

# === Zusätzliche Parameter für Proxmox Virtual Environment (PVE) ===
net.ipv4.ip_forward = 1            # Für LXC/Netzwerkbrücken: IPv4-Forwarding aktivieren
user.max_user_namespaces = 15000   # User-Namespaces für LXC erlauben
# net.ipv6.conf.all.forwarding = 1 # Optional: IPv6-Forwarding (z.B. für Cluster)
EOF
      ;;
    4)
      # Proxmox Backup Server: meist kein IP-Forwarding nötig, aber User-Namespaces ok
      cat >> "$TMPFILE" << 'EOF'

# === Zusätzliche Parameter für Proxmox Backup Server (PBS) ===
user.max_user_namespaces = 15000   # User-Namespaces für bestimmte Operationen erlauben
# net.ipv4.ip_forward bleibt 0     # Kein Routing nötig, PBS ist meist Storage-Server
EOF
      ;;
    1|*)
      # Nichts hinzufügen, Standard reicht
      ;;
  esac
done

# Ausgabe und Aktivierung
echo
echo "Die folgenden Kernelparameter werden in $OUTFILE gespeichert:"
echo "-----------------------------------------------------------"
cat "$TMPFILE"
echo "-----------------------------------------------------------"

read -rp "Wollen Sie diese Kernel-Konfiguration anwenden? (j/N): " confirm
if [[ "$confirm" =~ ^[JjYy]$ ]]; then
    sudo cp "$TMPFILE" "$OUTFILE"
    sudo sysctl --system
    echo "Konfiguration aktiviert."
else
    echo "Keine Änderungen wurden vorgenommen."
fi

rm "$TMPFILE"
