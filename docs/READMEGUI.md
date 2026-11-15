# CVEwatch – GUI & Report Guide

## What Does CVEwatch Do?

CVEwatch inventories your Windows device (hardware, installed software, drivers and services) and compares the installed software against the CISA Known Exploited Vulnerabilities (KEV) catalog. It then validates the findings against NIST NVD data to determine whether the installed version is actually affected. The Windows build itself is checked as well.

The result is a prioritized HTML report focused on vulnerabilities that are actively exploited in the real world.

✅ Local processing

✅ Security posture assessment

✅ KEV intelligence

✅ NVD version validation (programs and Windows build)

✅ HTML report in English and German

✅ No telemetry

---

<details>
<summary><b>Quick Start</b></summary>

1. Start the GUI:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\CVEwatchSCANme.ps1 -Gui
   ```

2. Click **Start scan** – preferably as administrator; the results are then more complete. If the window was not started as administrator, it offers to restart elevated.
3. Wait until all stages on the left are green. The first time, the NVD check can take a few minutes (the NVD rate-limits requests; this is normal and not a hang – with a free NVD API key it is about ten times faster).
4. The report opens in your browser. Read it top to bottom: first the management summary, then the KEV hits. Red and near the top = deal with it first.

That is all you need at the beginning. Everything else is fine-tuning.

</details>

<details>
<summary><b>The Window at a Glance</b></summary>

| Area | Purpose |
|------|---------|
| **Deutsch / English** (top) | Switches the window and the console output of the scan. The window is rebuilt in the other language (not possible while a scan is running). |
| **Help / Guide** (top) | Built-in guide with table of contents and search (Ctrl+F, F3). |
| **Process** | The eight scan stages with live progress. |
| **Options** | What is scanned and how (see below). |
| **Outbound connections** | Optional tests that contact third parties – all off by default. |
| **Log** | Live messages of the scan. |
| **Export buttons** | Open the newest Report (HTML), Inventory (CSV), Hits (JSON) or Log (TXT). Only clickable if the file exists. |

The scan runs as a separate process, so the window stays responsive.

</details>

<details>
<summary><b>Scan Workflow</b></summary>

1. System & hardware
2. Security posture
3. Network
4. Software inventory
5. Load KEV catalog
6. KEV matching
7. Version check (NVD)
8. Create HTML report

Progress is displayed live in the GUI, including an estimate of the remaining time during the NVD check.

</details>

<details>
<summary><b>Options</b></summary>

### KEV matching (default: on)

Matches the installed software against the CISA KEV catalog.

Disabled:
- Inventory, security posture and network only
- No vulnerability correlation

Command line: `-NoKev`

### + NVD version check (default: on)

Asks the NVD for each hit whether the installed version is in the vulnerable range and fetches the CVSS severity.

Disabled:
- Shows only that a product appears in KEV, without version check

Command line: `-NoVersionCheck`

### + Check Windows build (default: on)

Compares your exact Windows build with the KEV entries for Windows itself and shows which vulnerabilities your build still has and from which build they are fixed. Requires the NVD version check. Costs additional NVD requests; the first run without API key takes longer.

Command line: `-NoOsCheck` (additionally `-OsAllYears` checks entries older than your Windows release)

### NVD API key (optional)

Free key from nvd.nist.gov. Rate limits increase from:

- 5 requests / 30 seconds

to:

- 50 requests / 30 seconds

The key field is masked. The GUI passes the key to the scan via environment variable, not on the command line (command lines are visible to other users in the process list).

Command line: `-NvdApiKey` or environment variable `CVEWATCH_NVD_API_KEY`

### Use cache instead of downloading (default: off)

Uses locally cached KEV and NVD data.

Useful for:

- Offline operation
- Faster scans
- Temporary source outages

The price: newly added vulnerabilities may be missing. Command line: `-UseCache`

### NVD limit (default: on, 150 new requests per run)

Limits how many CVEs one run newly queries from the NVD; cached CVEs do not count. If the limit is not enough, the report clearly says **"Scan incomplete"** – simply scan again, the second run fetches the missing CVEs. Without the limit everything is checked in one run; without an API key this can take a long time.

Command line: `-NvdMaxCves <number>` or `-NoNvdLimit`

### Outbound connections (all off by default)

| Option | Target | Command line |
|--------|--------|--------------|
| Determine public IP | api.ipify.org / ifconfig.me | `-PublicIP` |
| Measure internet latency | www.google.de / www.devicentra.de | `-Latency` |
| Download speed test | crusadersoft.com (10 MB) | `-SpeedTest` |
| All three | | `-External` |

</details>

<details>
<summary><b>Administrator Rights</b></summary>

Without administrator rights the scan still runs, but BitLocker status, Defender exclusions, SSD health values and parts of the driver and service data are missing.

- **GUI:** before the scan, a dialog offers *Yes* = restart as administrator, *No* = scan anyway, *Cancel* = back.
- **Console:** in an interactive session it waits 10 seconds (key **N** = cancel, Enter = start now) and then starts on its own – it never blocks.
- **Rollouts:** `-AllowNonAdmin` continues silently, `-RequireAdmin` exits immediately with exit code 5.

</details>

<details>
<summary><b>Security Posture Assessment</b></summary>

Checks include:

- Patch status and pending restart
- Operating system support status (by Windows version and edition, LTSC and Windows Server; a notice appears 120 days before the end of support)
- Secure Boot, BitLocker, TPM
- RDP, SMBv1, UAC, NTLM level
- Registered antivirus products
- Local administrators, guest account, autologon
- SMB shares
- LSA protection, VBS / HVCI, Credential Guard
- Entra ID / domain join
- Listening ports

### Microsoft Defender

- Product, engine and signature version
- Real-time, behavior and tamper protection
- Cloud protection (MAPS), PUA and network protection
- Controlled folder access
- ASR rules
- Exclusions
- Last quick and full scan

If another antivirus is registered (e.g. ESET), a switched-off Defender is not reported as a risk.

### Storage

- HDD, SSD, NVMe
- USB storage

Including:

- Health status, wear and temperature (SSD, with admin rights)
- Capacity and usage per volume
- BitLocker protection (unencrypted USB drives are flagged)

</details>

<details>
<summary><b>Understanding the Report</b></summary>

### Structure

1. **Management summary** – traffic light, findings by severity, top actions with effort, what is fine, and the **scope of this scan** (what could not be checked and why).
2. **Actively exploited vulnerabilities** – one card per product, collapsed by default.
3. System & hardware, storage, network, security posture, Defender, listening ports.
4. Full inventory with search and source filter (works offline in the browser).

### Buttons at the top

- **Deutsch / English** – switches the whole report, including mouse-over explanations
- Print management summary / print full report (choose "Save as PDF" in the print dialog; the language currently shown is printed)
- Expand / collapse all

### Each CVE row shows

- **CVE** – link to the NVD, CVSS severity, orange dot = known ransomware use
- **Match & version** – confidence (*High* = product and vendor match, *Medium* = product name only), installed version, vulnerable ranges according to the NVD (the range containing your version is red), fixed version, verdict with reason
- **CISA due date** – red = overdue, orange = due within 14 days
- **Vulnerability** – name, CISA description (English, long texts expandable) and required action

### Verdicts

| Verdict | Meaning |
|---------|---------|
| **Affected** | Your version is in a vulnerable range according to the NVD |
| **Probably patched** | Your version is outside all listed vulnerable ranges |
| **Unclear** | No reliable statement possible – the reason is shown |

Hits rated "Probably patched" are collapsed per product (toggle row in the table, visible when printing).

### Prioritization

Findings are sorted by:

1. Ransomware association
2. CISA remediation deadline (overdue first)
3. Version validation result
4. Match confidence
5. CVSS score

Deliberately without EPSS: for KEV entries, exploitation is already confirmed.

### Colors

🔴 Affected / overdue

🟠 Ransomware related / due soon

🟢 Probably patched

Findings marked **NEW** were not present during the previous scan of this device.

### Special cases

- **Chrome and Edge:** Chromium entries in KEV apply to both. For Edge the NVD ranges are used if they name Edge; otherwise the verdict is derived from the major version ("Derived: …").
- **Windows itself:** the report compares your build with the fix build per Windows release. Entries that only affect other releases are only counted in the management summary.
- **Microsoft 365 Apps (Click-to-Run):** no version comparison possible; version and update status are shown instead.
- **Scan incomplete:** an orange notice at the top means the NVD limit was reached – scan again.

### Listening ports

| Color | Meaning |
|-------|---------|
| 🟢 Windows default | Common Windows service on its standard port, opened by the expected process |
| 🔵 Known service | Web server, database, printer … – check whether intended |
| 🟠 Remote access / unusual | RDP, SSH, VNC, remote support tools, or a standard port opened by an unexpected process |
| 🔴 Outdated / unencrypted | Telnet, FTP |
| ⚪ Unknown | Application-specific port – check whether the software is known |

Green does not mean "safe", but "expected". Every classification has a mouse-over explanation.

</details>

<details>
<summary><b>Reports & Automation</b></summary>

Generated outputs (under `%USERPROFILE%\CVEwatch\assets\<computer name>\`):

- HTML report (English and German)
- CSV inventory
- JSON findings
- Log file
- summary.json

Exit codes:

| Code | Meaning |
|--------|--------|
| 0 | No open findings (or KEV matching skipped) |
| 1 | Cancelled by the user before the scan (console without admin rights) |
| 2 | KEV hits with open version (not rated as patched) |
| 3 | Overdue CISA remediation deadline |
| 4 | Confirmed vulnerable version |
| 5 | Administrator rights missing and `-RequireAdmin` set |

Hits rated "Probably patched" do not count for codes 2 and 3. Ideal for scheduled tasks and monitoring systems. Details: [READMETECH.md](READMETECH.md).

</details>

<details>
<summary><b>Privacy & Data Sources</b></summary>

Everything runs locally.

No inventory data is transmitted.

### Default Connections

- CISA KEV catalog (cisa.gov)
- NIST NVD (nvd.nist.gov)

Only CVE identifiers are requested.

### Optional Connections

- api.ipify.org
- ifconfig.me
- www.google.de
- www.devicentra.de
- crusadersoft.com (10 MB speed test)

The report lists exactly which connections were made during that run.

### Privacy

✅ No telemetry

✅ No inventory upload

✅ No cloud dependency

✅ No software inventory sharing

Reports remain on the local device. They contain personal data (host name, user accounts, IP/MAC addresses, installed software): share them only with authorized persons.

Privacy policy:

https://crusadersoft.com/#datenschutz

This product uses data from the NVD API but is not endorsed or certified by the NVD.

</details>

<details>
<summary><b>Enterprise Features</b></summary>

The Community Edition intentionally scans only the local device – also for security reasons, so that it cannot be used to scan arbitrary networks.

Enterprise features include:

- FleetScan
- Multi-report aggregation
- Central dashboards
- Historical tracking
- Fleet analytics
- Network discovery
- Network scanning
- Dedicated CVEwatch instances

More information:

- https://crusadersoft.com
- https://cvewatch.de

</details>
