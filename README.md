# utils

Eine Sammlung von Linux-Systemhärtungs-Skripten für Ble1st.

## Enthaltene Skripte

### sysctl.sh (Version 1.1.0)
Interaktives Skript zur Kernel-Härtung für generische Linux-Server mit optionalen spezifischen Einstellungen für Docker oder Proxmox.

**Funktionen:**
- Kernel-Parameter Hardening
- Netzwerk-Sicherheitskonfiguration
- Spezielle Konfigurationen für Docker, Proxmox VE und Proxmox Backup Server
- Automatische Backup-Erstellung vor Änderungen

**Verwendung:**
```bash
sudo ./sysctl.sh          # Interaktive Ausführung
./sysctl.sh --version     # Versionsinformation anzeigen
./sysctl.sh -v            # Versionsinformation anzeigen (kurz)
```

### deb_hard (Version 1.0.0)
Debian 12 Hardening Skript für KRITIS nach BSI, CIS und NIDS Standards.

**Funktionen:**
- Systemaktualisierung und automatische Sicherheitsupdates
- Passwortrichtlinien-Härtung
- SSH-Server Sicherheitskonfiguration
- Netzwerk- und Kernel-Härtung
- Auditd-Konfiguration
- Fail2Ban-Setup
- Mail-System-Konfiguration

**Verwendung:**
```bash
sudo ./deb_hard          # Vollständige Systemhärtung
./deb_hard --version     # Versionsinformation anzeigen
./deb_hard -v            # Versionsinformation anzeigen (kurz)
```

## Systemanforderungen

- Linux-System (Debian/Ubuntu empfohlen für deb_hard)
- Root-Berechtigung für die Ausführung
- Bash Shell

## Versionsinformationen

Beide Skripte unterstützen die Abfrage der Versionsinformation:
```bash
./sysctl.sh --version
./deb_hard --version
```