# CVEwatch Asset Scanner – Security

[English](#english) · [Deutsch](#deutsch)

---

## English

### 1. Verify the file before running it

Every release publishes a SHA-256 checksum. It is shown in **three independent places**, so tampering is only undetected if all three are compromised at once:

- GitHub release notes: <https://github.com/CrusaderBoy/CVEwatch/releases>
- <https://cvewatch.de>
- <https://crusadersoft.com>

| Version | File | SHA-256 |
|---|---|---|
| 4.0 | `CVEwatchSCANme.ps1` | `5B2A21E5E998F94B30E0F3E6D20D0880773CB7BC95F035254556A5DFBB3EEA7E` |

**Check it:**

```powershell
(Get-FileHash .\CVEwatchSCANme.ps1 -Algorithm SHA256).Hash
```

The result must match **all three** published values exactly. Without PowerShell: `certutil -hashfile CVEwatchSCANme.ps1 SHA256`.

**If the hash does not match: do not run the file.** Download it again from the GitHub release. If it still does not match, please report it (see section 7).

**Do not re-save the file before checking.** The script is stored as UTF-8 *with* BOM and Windows line endings (CRLF). Opening and saving it in an editor can change both, which changes the hash. Without the BOM, Windows PowerShell 5.1 can no longer read the file correctly.

### 2. Downloaded file is blocked (Mark of the Web)

Windows marks files downloaded from the internet. Once you have verified the hash, you can remove the mark:

```powershell
Unblock-File .\CVEwatchSCANme.ps1
```

Alternatively, start it with `-ExecutionPolicy Bypass` as shown in the README. This only applies to this one process and does not change your system's execution policy.

### 3. Code signing

The script is currently **not** Authenticode-signed. Integrity is verified by the SHA-256 hash above. Environments that enforce `AllSigned` have to sign the script with their own certificate, or allow it explicitly.

### 4. What the scanner does and does not do

- **Read-only.** The scanner changes no system settings, services, registry values or software. It only writes its own output files (see section 6).
- **No telemetry.** No inventory data, report or other device data is uploaded anywhere.
- **Administrator rights** are optional. They are only used to *read* more (BitLocker status, Defender exclusions, SSD health). Without them, the scan runs with gaps and says so in the report.
- **Other users' software:** when run as administrator or SYSTEM, the scanner *reads* the uninstall entries of users who are currently signed in (`HKEY_USERS\<SID>`; local, AD and Entra ID accounts). It does not load the profiles of users who are not signed in, and it changes nothing.
- **32-bit PowerShell** (e.g. Intune without "64-bit host"): the script restarts itself in 64-bit PowerShell. Otherwise 64-bit programs would be invisible.

### 5. Network connections

| Target | Purpose | When |
|---|---|---|
| `www.cisa.gov` | CISA KEV catalog (official source, no mirrors) | Default, unless `-NoKev` or `-UseCache` |
| `services.nvd.nist.gov` | CVE details per hit (only CVE IDs are sent) | Default, unless `-NoVersionCheck` or cache hit |
| `api.ipify.org`, `ifconfig.me` | Public IP address (third-party services) | Only with `-PublicIP` |
| `www.google.de`, `www.devicentra.de` | Latency (ping) | Only with `-Latency` |
| `crusadersoft.com` | 10 MB speed test file (download only) | Only with `-SpeedTest` |

`-External` turns on the three opt-in tests at once. Every target sees your public IP address. Links to crusadersoft.com and cvewatch.de in the window and the report only open when you click them.

**NVD API key:** prefer the environment variable `CVEWATCH_NVD_API_KEY` over `-NvdApiKey`, because command line arguments are visible to other users in the process list. The GUI hands the key to the scan process only through the environment. The key is sent only to the NVD, in the `apiKey` header, and is never written to any file.

### 6. Output files and personal data

| Run as | Folder |
|---|---|
| User / administrator | `%USERPROFILE%\CVEwatch\assets\<computer name>\` |
| SYSTEM (Intune, SCCM, scheduled task) | `%ProgramData%\CVEwatch\assets\` – access limited to SYSTEM and Administrators |

Reports, CSV, JSON and logs contain **personal and security-relevant data**: host name, user accounts, IP/MAC addresses and a list of exploitable vulnerabilities on this device. Only share them with authorized people. Nothing is deleted automatically, so remove old reports yourself when you no longer need them. The cache files (`kev_catalog.json`, `nvd_cpe_cache.json`) only contain public CVE data.

Privacy policy: <https://crusadersoft.com/#datenschutz>

### 7. Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's private reporting instead:
<https://github.com/CrusaderBoy/CVEwatch/security/advisories/new>

Please include the version, the steps to reproduce it and the impact. Reports are confirmed and fixed as quickly as possible, and reporters are credited if they want.

---

## Deutsch

### 1. Datei vor dem Ausführen prüfen

Zu jedem Release wird eine SHA-256-Prüfsumme veröffentlicht. Sie steht an **drei unabhängigen Stellen**. Eine Manipulation bleibt also nur unbemerkt, wenn alle drei gleichzeitig kompromittiert sind:

- GitHub-Release-Notes: <https://github.com/CrusaderBoy/CVEwatch/releases>
- <https://cvewatch.de>
- <https://crusadersoft.com>

| Version | Datei | SHA-256 |
|---|---|---|
| 4.0 | `CVEwatchSCANme.ps1` | `5B2A21E5E998F94B30E0F3E6D20D0880773CB7BC95F035254556A5DFBB3EEA7E` |

**Prüfen:**

```powershell
(Get-FileHash .\CVEwatchSCANme.ps1 -Algorithm SHA256).Hash
```

Das Ergebnis muss mit **allen drei** veröffentlichten Werten exakt übereinstimmen. Ohne PowerShell: `certutil -hashfile CVEwatchSCANme.ps1 SHA256`.

**Stimmt der Hash nicht: Datei nicht ausführen.** Lade sie erneut aus dem GitHub-Release herunter. Stimmt er dann immer noch nicht, melde es bitte (siehe Abschnitt 7).

**Datei vor der Prüfung nicht neu speichern.** Das Skript ist als UTF-8 *mit* BOM und mit Windows-Zeilenenden (CRLF) gespeichert. Öffnen und Speichern in einem Editor kann beides verändern, und damit ändert sich auch der Hash. Ohne BOM kann Windows PowerShell 5.1 die Datei nicht mehr korrekt lesen.

### 2. Heruntergeladene Datei ist blockiert (Mark of the Web)

Windows markiert Dateien, die aus dem Internet stammen. Nachdem du den Hash geprüft hast, kannst du die Markierung entfernen:

```powershell
Unblock-File .\CVEwatchSCANme.ps1
```

Alternativ startest du das Skript wie in der README mit `-ExecutionPolicy Bypass`. Das gilt nur für diesen einen Prozess und ändert die Ausführungsrichtlinie deines Systems nicht.

### 3. Code-Signatur

Das Skript ist derzeit **nicht** per Authenticode signiert. Die Integrität prüfst du über den SHA-256-Hash oben. In Umgebungen mit `AllSigned`-Richtlinie muss das Skript mit einem eigenen Zertifikat signiert oder ausdrücklich freigegeben werden.

### 4. Was der Scanner tut und was nicht

- **Nur lesend.** Der Scanner ändert keine Systemeinstellungen, Dienste, Registry-Werte oder Software. Er schreibt nur seine eigenen Ergebnisdateien (siehe Abschnitt 6).
- **Keine Telemetrie.** Es werden keine Inventardaten, Berichte oder sonstigen Gerätedaten irgendwohin hochgeladen.
- **Administratorrechte** sind optional. Sie dienen nur dazu, mehr zu *lesen* (BitLocker-Status, Defender-Ausschlüsse, SSD-Gesundheit). Ohne sie läuft der Scan mit Lücken und weist im Report darauf hin.
- **Software anderer Benutzer:** Als Administrator oder SYSTEM *liest* der Scanner die Deinstallationseinträge gerade angemeldeter Benutzer (`HKEY_USERS\<SID>`; lokale, AD- und Entra-ID-Konten). Profile nicht angemeldeter Benutzer werden nicht eingehängt, und es wird nichts verändert.
- **32-Bit-PowerShell** (z. B. Intune ohne „64-Bit-Host“): Das Skript startet sich selbst in der 64-Bit-PowerShell neu. Sonst wären 64-Bit-Programme unsichtbar.

### 5. Netzwerkverbindungen

| Ziel | Zweck | Wann |
|---|---|---|
| `www.cisa.gov` | CISA-KEV-Katalog (offizielle Quelle, keine Mirror) | Standard, außer mit `-NoKev` oder `-UseCache` |
| `services.nvd.nist.gov` | CVE-Details pro Treffer (es werden nur CVE-Kennungen gesendet) | Standard, außer mit `-NoVersionCheck` oder bei Cache-Treffer |
| `api.ipify.org`, `ifconfig.me` | Öffentliche IP-Adresse (Drittanbieter) | Nur mit `-PublicIP` |
| `www.google.de`, `www.devicentra.de` | Latenz (Ping) | Nur mit `-Latency` |
| `crusadersoft.com` | 10-MB-Testdatei für den Speedtest (nur Download) | Nur mit `-SpeedTest` |

`-External` schaltet die drei Opt-in-Tests auf einmal ein. Jedes Ziel sieht deine öffentliche IP-Adresse. Links zu crusadersoft.com und cvewatch.de im Fenster und im Report öffnen sich nur, wenn du sie anklickst.

**NVD-API-Key:** Nutze lieber die Umgebungsvariable `CVEWATCH_NVD_API_KEY` statt `-NvdApiKey`, denn Kommandozeilen-Argumente sind für andere Benutzer in der Prozessliste sichtbar. Die GUI gibt den Key nur über die Umgebung an den Scan-Prozess weiter. Der Key geht ausschließlich im Header `apiKey` an die NVD und wird in keine Datei geschrieben.

### 6. Ergebnisdateien und personenbezogene Daten

| Ausgeführt als | Ordner |
|---|---|
| Benutzer / Administrator | `%USERPROFILE%\CVEwatch\assets\<Computername>\` |
| SYSTEM (Intune, SCCM, geplanter Task) | `%ProgramData%\CVEwatch\assets\` – Zugriff nur für SYSTEM und Administratoren |

Reports, CSV, JSON und Logs enthalten **personenbezogene und sicherheitsrelevante Daten**: Hostname, Benutzerkonten, IP-/MAC-Adressen und eine Liste ausnutzbarer Schwachstellen dieses Geräts. Gib sie nur an Berechtigte weiter. Es wird nichts automatisch gelöscht, entferne alte Reports also selbst, wenn du sie nicht mehr brauchst. Die Cache-Dateien (`kev_catalog.json`, `nvd_cpe_cache.json`) enthalten nur öffentliche CVE-Daten.

Datenschutzerklärung: <https://crusadersoft.com/#datenschutz>

### 7. Schwachstelle melden

Bitte **kein** öffentliches Issue für Sicherheitsprobleme eröffnen. Nutze stattdessen die private Meldefunktion von GitHub:
<https://github.com/CrusaderBoy/CVEwatch/security/advisories/new>

Bitte gib die Version, die Schritte zum Nachstellen und die Auswirkung an. Meldungen werden so schnell wie möglich bestätigt und behoben, und auf Wunsch wird der Melder genannt.
