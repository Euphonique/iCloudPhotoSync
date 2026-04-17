# Synology DSM 7.1+ Native App — Toolkit Setup

## Hinweise zu DSM 7.1

Das Paket unterstützt sowohl DSM 7.1 als auch DSM 7.2+. Auf DSM 7.1 gibt es zwei Unterschiede:

### Python 3

DSM 7.2 liefert Python 3 als Systembinary (`/usr/bin/python3`). Auf DSM 7.1 ist Python 3 möglicherweise **nicht vorinstalliert**. Falls die Installation fehlschlägt mit der Meldung *"Python 3 benötigt"*:

1. **Paketzentrum** → Python3 installieren (falls verfügbar), oder
2. **SynoCommunity** als Paketquelle hinzufügen (`https://packages.synocommunity.com`) und Python3 von dort installieren.

### Zielordner `/volume1/iCloudPhotos`

Auf DSM 7.2 erstellt `data-share` den freigegebenen Ordner automatisch. Auf DSM 7.1 legt das Installationsskript das Verzeichnis als Fallback an — es ist dann aber möglicherweise kein vollwertiger *Shared Folder* (d.h. nicht über SMB/AFP im Netzwerk sichtbar). Falls Sie den Ordner per Netzwerk erreichen möchten:

1. **DSM → Systemsteuerung → Freigegebener Ordner** → *Erstellen*
2. Name: `iCloudPhotos`, Speicherort: Volume 1
3. Falls der Ordner bereits existiert: den vorhandenen Ordner als Shared Folder registrieren.

---

## Voraussetzungen

### 1. Linux-Umgebung (Toolkit läuft NICHT unter Windows)

Das Toolkit nutzt `chroot` und ist Linux-only. Unter Windows 11 nutzen wir **WSL2**:

```bash
# PowerShell (Admin):
wsl --install -d Ubuntu
```

### 2. Toolkit-Komponenten

| Komponente | Quelle |
|---|---|
| **pkgscripts-ng** | https://github.com/SynologyOpenSource/pkgscripts-ng (Branch `DSM7.1` or `DSM7.2`) |
| **Build-Environment** | Wird automatisch von `EnvDeploy` heruntergeladen |
| **Beispielpakete** | https://github.com/SynologyOpenSource/ExamplePackages |
| **Minimal-Paket** | https://github.com/SynologyOpenSource/minimalPkg |
| **Developer Guide (PDF)** | https://global.synologydownload.com/download/Document/Software/DeveloperGuide/Os/DSM/All/enu/DSM_Developer_Guide_7_enu.pdf |
| **Developer Guide (Web)** | https://help.synology.com/developer-guide/ |

---

## Toolkit einrichten

### Schritt 1: Ubuntu-Pakete installieren

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-pip cifs-utils
```

### Schritt 2: Toolkit-Verzeichnis anlegen

```bash
sudo mkdir -p /toolkit
sudo chown $USER:$USER /toolkit
cd /toolkit
```

### Schritt 3: pkgscripts-ng klonen (DSM 7.1 Branch)

```bash
git clone https://github.com/SynologyOpenSource/pkgscripts-ng.git
cd pkgscripts-ng
git checkout DSM7.1
```

### Schritt 4: Build-Environment deployen

```bash
# Verfügbare Plattformen anzeigen:
sudo ./EnvDeploy -v 7.1 --list

# Environment für Zielplattform deployen (z.B. geminilake):
sudo ./EnvDeploy -v 7.1 -p geminilake
```

#### Gängige Plattformen

| Platform | Architektur | NAS-Modelle |
|---|---|---|
| `geminilake` | x86_64 | DS220+, DS420+, DS720+, DS920+ |
| `apollolake` | x86_64 | DS218+, DS418, DS918+ |
| `v1000` | x86_64 | DS1621+, DS1821+ |
| `rtd1619b` | armv8 | DS223, DS224+ |

Für plattformunabhängige Pakete (kein nativer Code): `arch="noarch"` in INFO.sh.

---

## Verzeichnisstruktur

### Toolkit (nach Setup)

```
/toolkit/
├── pkgscripts-ng/          # Build-Framework (von GitHub)
│   ├── EnvDeploy            # Environment-Deployment
│   ├── PkgCreate.py         # Paket-Build
│   └── include/
│       └── pkg_util.sh      # Helper-Funktionen
├── build_env/              # Chroot-Umgebung (von EnvDeploy)
│   └── ds.geminilake-7.1/
├── source/                 # Paket-Quellcode
│   └── iCloudPhotoSync/
├── toolkit_tarballs/       # Gecachte Environment-Tarballs
└── result_spk/             # Fertige .spk Dateien
```

### Unser Paket

```
/toolkit/source/iCloudPhotoSync/
├── INFO.sh                 # Metadaten-Skript (generiert INFO)
├── Makefile                # Build-Anweisungen
├── PACKAGE_ICON.PNG        # 72x72 Icon
├── PACKAGE_ICON_256.PNG    # 256x256 Icon
├── SynoBuildConf/          # Toolkit-Build-Konfiguration
│   ├── depends             # DSM-Version & Abhängigkeiten
│   ├── build               # Kompilier-Skript
│   └── install             # Pack-Skript (erstellt .spk)
├── conf/
│   └── privilege           # Berechtigungen (Pflicht für DSM 7)
├── scripts/
│   ├── start-stop-status   # Start/Stop/Status Handler
│   ├── preinst             # Vor Installation
│   ├── postinst            # Nach Installation
│   ├── preuninst           # Vor Deinstallation
│   ├── postuninst          # Nach Deinstallation
│   ├── preupgrade          # Vor Upgrade
│   └── postupgrade         # Nach Upgrade
└── ui/                     # DSM Desktop UI
    ├── config              # App-Registrierung (JSON)
    ├── index.js            # Vue.js Entry-Point
    └── images/             # Icons (16, 24, 32, 48, 64, 256 px)
```

---

## Build-Befehle

```bash
cd /toolkit/pkgscripts-ng

# Voller Build (kompilieren + packen):
sudo ./PkgCreate.py -v 7.1 -p geminilake -c iCloudPhotoSync

# Nur packen (ohne Kompilierung, z.B. für noarch):
sudo ./PkgCreate.py -v 7.1 -p geminilake -I iCloudPhotoSync

# Nur kompilieren (ohne packen):
sudo ./PkgCreate.py -v 7.1 -p geminilake iCloudPhotoSync
```

### Ausgabe

Die fertige `.spk` Datei liegt unter:

```
/toolkit/result_spk/iCloudPhotoSync-1.0.0-0001/iCloudPhotoSync-noarch-1.0.0-0001.spk
```

---

## Wichtige Dateien im Detail

### INFO.sh

Generiert die Paket-Metadaten. Pflichtfelder:

| Feld | Beschreibung | Beispiel |
|---|---|---|
| `package` | Interner Name (keine Sonderzeichen) | `"iCloudPhotoSync"` |
| `version` | Format: feature-build | `"1.0.0-0001"` |
| `os_min_ver` | Minimale DSM-Version | `"7.1-42218"` |
| `arch` | CPU-Architektur | `"noarch"` |
| `maintainer` | Entwickler | `"Your Name"` |
| `description` | Kurzbeschreibung | `"iCloud Photo Sync"` |

Optionale Felder für UI-Apps:

| Feld | Beschreibung |
|---|---|
| `displayname` | Anzeigename im Package Center |
| `dsmuidir` | UI-Ordner in package.tgz (z.B. `"ui"`) |
| `dsmappname` | App-Namespace (z.B. `"SYNO.SDS.iCloudPhotoSync"`) |

### conf/privilege (Pflicht für DSM 7)

```json
{
    "defaults": {
        "run-as": "package"
    }
}
```

In DSM 7 müssen alle Pakete als `"package"` User laufen (nicht als root).

### scripts/start-stop-status

```bash
#!/bin/sh
case $1 in
    start)  exit 0 ;;
    stop)   exit 0 ;;
    status) exit 0 ;;  # 0=running, 3=stopped
esac
```

### ui/config (Native DSM App, kein iframe)

```json
{
    "SYNO.SDS.iCloudPhotoSync.Instance": {
        "type": "app",
        "title": "iCloud Photo Sync",
        "appWindow": "SYNO.SDS.iCloudPhotoSync.Instance",
        "allUsers": true,
        "allowMultiInstance": false,
        "icon": "images/icon_{0}.png"
    }
}
```

---

## Nächste Schritte

1. [ ] WSL2 / Ubuntu einrichten
2. [ ] Toolkit klonen und Environment deployen
3. [ ] Paket-Skeleton erstellen (alle Dateien oben)
4. [ ] Ersten Build ausführen
5. [ ] .spk auf der Synology installieren und testen
