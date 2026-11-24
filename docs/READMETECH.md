# CVEwatch – Technical Details

## Overview

CVEwatch is a single PowerShell script (`CVEwatchSCANme.ps1`) that runs locally on one Windows device. The GUI (`-Gui`) is only a front end: it starts the same script as a separate process with matching parameters and reads its progress from a status file.

- Runs on Windows PowerShell 5.1 and PowerShell 7
- Windows 10, Windows 11, Windows Server 2016 and newer
- No installation, no agent, no external modules

---

## Parameters

All parameters are switches unless a value is shown.

### Interface and output

| Parameter | Description |
|-----------|-------------|
| `-Gui` | Start the graphical interface instead of a console run |
| `-Lang en\|de` | Language of window and console (default: `en`). The HTML report always contains both languages |
| `-NoOpen` | Do not open the report automatically at the end (useful for automation) |

### Scope and freshness

| Parameter | Description |
|-----------|-------------|
| `-NoKev` | Skip KEV matching – inventory and posture only |
| `-NoVersionCheck` | Skip only the NVD version check (no version ranges, no CVSS, no Windows build check) |
| `-NoOsCheck` | Skip only the Windows build check |
| `-OsAllYears` | Build check also for KEV entries older than the installed Windows release |
| `-UseCache` | Take KEV and NVD data from the local cache instead of downloading |
| `-NvdApiKey <key>` | Use an NVD API key. Safer: environment variable `CVEWATCH_NVD_API_KEY` (command lines are visible in the process list) |
| `-NvdMaxCves <n>` | Maximum number of **new** NVD requests per run (default: 150; cached CVEs do not count; `0` = unlimited) |
| `-NoNvdLimit` | No limit – check all CVEs in one run |

### Outbound connections (all off by default)

| Parameter | Description |
|-----------|-------------|
| `-PublicIP` | Determine the public IP (api.ipify.org, fallback ifconfig.me) |
| `-Latency` | Ping www.google.de, fallback www.devicentra.de |
| `-SpeedTest` | Download a 10 MB test file from crusadersoft.com |
| `-External` | Shorthand for all three |

### Administrator rights

| Parameter | Description |
|-----------|-------------|
| *(none)* | Interactive console without admin rights: 10 seconds to cancel (key N), then the scan starts on its own. Never blocks in non-interactive sessions |
| `-AllowNonAdmin` | Continue silently without admin rights (warning only in the log) |
| `-RequireAdmin` | Without admin rights exit immediately with exit code 5, nothing is collected |

### Internal

| Parameter | Description |
|-----------|-------------|
| `-StatusFile <path>` | Progress file for the GUI – do not set manually |

### Examples

```powershell
# GUI in German
powershell -ExecutionPolicy Bypass -File .\CVEwatchSCANme.ps1 -Gui -Lang de

# Quick run without browser
powershell -ExecutionPolicy Bypass -File .\CVEwatchSCANme.ps1 -UseCache -NoOpen

# Everything including network tests
powershell -ExecutionPolicy Bypass -File .\CVEwatchSCANme.ps1 -External

# Scheduled task that only reports via exit code
powershell -ExecutionPolicy Bypass -File .\CVEwatchSCANme.ps1 -RequireAdmin -NoOpen
```

---

## Data Collection

CVEwatch combines several inventory sources to build an asset inventory.

### System information

- Operating system, edition, display version and full build (`10.0.<build>.<UBR>`)
- System model, mainboard, BIOS, serial number (BIOS → enclosure → system product, junk values discarded)
- CPU, GPU, memory
- All physical disks with their volumes (HDD, SSD, NVMe, USB), health, wear/temperature (admin), BitLocker per volume
- Network configuration (local IP, MAC, gateway incl. local ping, DNS)
- Security configuration (see Security Posture)

### Software inventory

| Source | Notes |
|--------|-------|
| Registry (uninstall keys, HKLM + WOW6432Node + HKCU) | Name, version and publisher; system components excluded |
| Winget | `winget list --source winget`, if winget is installed |
| AppX | `Get-AppxPackage`; under PowerShell 7 via the Windows PowerShell compatibility layer, fallback: AppX package repository in the registry |
| Running processes | File version and company name from the executable |
| Services | Inventory only – no version, therefore not matched |
| Drivers | `Win32_PnPSignedDriver` with version and manufacturer |

Entries are deduplicated per source by name and version. Short process names (`chrome`, `msedge`, `code`, `pwsh` …) are mapped to product names by **exact** match only.

Combining multiple sources significantly increases coverage compared to uninstall entries alone.

---

## Vulnerability Detection Workflow

CVEwatch uses a two-stage detection model.

### Stage 1: KEV correlation

The software inventory is matched against the CISA KEV catalog, downloaded directly from cisa.gov (no third-party mirrors).

Purpose:

> Identify products that are associated with vulnerabilities currently being exploited in real-world attacks.

No version validation happens at this stage, because the KEV catalog does not provide machine-readable version ranges.

### Stage 2: NVD version validation

For every KEV match, CVEwatch retrieves the CVE from the NVD API 2.0 and compares the installed version with the vulnerable CPE ranges (`versionStartIncluding/Excluding`, `versionEndIncluding/Excluding` or an exact version). The CVSS base score is taken from the same response (preference: v4.0 > v3.1 > v3.0 > v2, NVD primary rating first).

Possible outcomes:

| Report (EN) | Report (DE) | Internal key in JSON | Meaning |
|-------------|-------------|----------------------|---------|
| Affected | Betroffen | `Betroffen` | Installed version is in a vulnerable range |
| Probably patched | Vermutlich gepatcht | `Vermutlich gepatcht` | Outside all listed vulnerable ranges |
| Unclear | Unklar | `Unklar` | No reliable statement (reason in `VerdictReason`) |
| No version | keine Version | `keine Version` | Inventory version not usable |
| Not checked | nicht geprüft | `nicht geprüft` | Version check disabled |

A CPE entry **without** any version boundary is never rated "Affected" – it only means the NVD does not narrow it down, so the result is "Unclear".

Products with several installed versions (registry/AppX) are checked per version.

### Windows build check

KEV entries for Windows itself (product names such as Windows, Win32k, SMBv3 …) are not matched by name. Instead:

1. The installed build is mapped to a release (e.g. 26100 → `windows_11_24h2`, 20348 → `windows_server_2022`). Unknown newer Windows 11 releases are mapped via the display version (e.g. `26H2`).
2. For each Windows KEV entry the NVD CPE ranges of **that release** are compared with the full build number.
3. Entries listed only for other releases are counted, not shown.
4. If the NVD does not list the release for **any** checked CVE (typically a brand-new release not yet recorded), there is **no all-clear**: the report says the build check is not meaningful.
5. KEV entries older than the release (CVE year before the release) are skipped by default to save requests (`-OsAllYears` checks them; a few known exceptions are always checked).
6. Releases out of regular support are not build-checked (the NVD lists no build boundaries there).

### Chromium-based browsers

Chromium entries in KEV are filed under vendor Google. They are matched to Google Chrome and Microsoft Edge. For Edge, the NVD ranges for `edge_chromium` are used if present; otherwise the verdict is derived from the Chrome fix version (Edge major version = Chromium major version). Old EdgeHTML entries (≤ 2020) are rated as not affecting today's Edge.

### Known coverage gaps

The report lists them under "Scope of this scan" instead of silently showing "no hits":

- Microsoft 365 Apps (Click-to-Run): builds are not comparable with NVD ranges (from MSI installations); version and update status are shown from the registry.
- Brave, Vivaldi, Opera: own version numbers without reliable mapping to Chromium.

---

## Matching Heuristics

Product identification uses:

- Tokenized product names (lower case, version numbers removed, noise words such as "update", "runtime", "x64" ignored)
- Strong tokens (≥ 4 characters) and weak tokens (3 characters or whitelisted short names like `7z`, `f5`)
- Vendor cross-check against the program name and publisher
- Rule tables for known naming differences (e.g. KEV "Firefox and Thunderbird", "TeamViewer Desktop", "VMware Tools", "win.rar GmbH" vs. "RARLAB")
- Ignore rules for programs that only share a name (e.g. Edge Update, .NET Native runtime packages)

Rules:

- Matches based on a single or a weak token require a matching vendor.
- If the program's publisher is known but does **not** match the KEV vendor, there is no match (different product with a similar name).

Each result receives a confidence rating:

### High confidence

Product **and** vendor match.

### Medium confidence

Only the product name matches (product names with at least two meaningful words; publisher unknown).

There is no "low" rating in practice: weaker indications are not reported at all.

Confidence and basis remain visible in reports.

### Extending the rules

All tables are at the top of the matcher section (between `# >>> MATCHER-KERN-START` and `# <<< MATCHER-KERN-ENDE`):

| Table | Purpose |
|-------|---------|
| `$script:KevProductRules` | Map a KEV vendor/product to one or more program names |
| `$script:InvAliasRules` | Extra name tokens for inventory items (e.g. Chrome → chromium) |
| `$script:InvIgnoreRules` | Programs without own KEV relevance |
| `$script:VendorAliasRules` | Extra vendor tokens (publisher aliases) |
| `$script:GenericProductTokens` | Words too generic to match alone |
| `$script:OsReleases` | Windows build → NVD CPE release |
| `$script:CoverageGapRules` | Known coverage gaps shown in the report |
| `$script:PortTable` | Port classification (name and hint in German and English) |

After changing the matcher, run the regression test (`MAINassetSCANNER.MatchTests.ps1`), which loads exactly this section.

---

## Security Posture Rules

### Operating system support

Evaluated per release **and** edition (lifecycle tables in the script, as of 11/2026):

- Windows 11: Home/Pro (24 months) vs. Enterprise/Education (36 months) per version; newer releases not yet in the table are treated as supported
- Windows 10: end of regular support 2025-10-14 (ESU not detectable)
- Windows 10/11 Enterprise LTSC / IoT Enterprise LTSC with their own lifecycles
- Windows Server 2008 R2 to 2025 (end of extended support)

Result: supported, **ends within 120 days** (medium finding), or **out of support** (critical finding).

### Defender and third-party antivirus

If an antivirus other than Defender is registered in Windows Security Center, a switched-off Defender, its signatures and its options are not reported as findings.

### Listening ports

Only TCP ports listening on non-loopback addresses are listed. Classification: Windows default (known port **and** expected process), remote access, outdated/unencrypted, known service, unusual (standard port with unexpected process), unknown. Dynamic ports ≥ 49152 owned by Windows system processes count as Windows default.

---

## Report Prioritization

Findings are sorted by actual operational risk:

1. Ransomware association
2. CISA due date (overdue first)
3. Version verdict (affected > unclear > probably patched)
4. Match confidence
5. CVSS score

Hits rated "Probably patched" are not a reason for urgency – they count neither for the overdue/ransomware warning nor for exit codes 2 and 3.

---

## Executive Summary Engine

Every report starts with an executive summary:

- Risk status (traffic light)
- Finding counts by severity (Critical, High, Medium, Info)
- Top remediation actions with effort
- What is fine
- Scope of this scan

All findings come from explicit, readable rules – no score, no hidden weighting. They are located in the section

```powershell
# >>> EXEC-SUMMARY BEGIN
...
# <<< EXEC-SUMMARY END
```

All texts there are bilingual (`L 'German' 'English'`).

---

## Caching Strategy

By default:

✅ KEV data is downloaded fresh

✅ NVD data is downloaded fresh

for every scan – new actively exploited vulnerabilities can appear at any time.

Exceptions and details:

| Cache | File | Behavior |
|-------|------|----------|
| KEV | `kev_catalog.json` | Refreshed on every run. With `-UseCache` used if younger than 24 h. If the download fails, an outdated cache is used as a fallback (stated in the report) |
| NVD | `nvd_cpe_cache.json` | Entries younger than 30 days are reused with `-UseCache`. Without `-UseCache`, cached data is only reused for CVEs that have been in KEV for more than 120 days (their ranges rarely change) |
| Diff | `<host>\last_state.json` | Hits of the previous run, used for the **NEW** marker. Not overwritten if the KEV catalog could not be loaded |

Cache files are located under `%USERPROFILE%\CVEwatch\assets` and can be deleted at any time.

```powershell
-UseCache
```

Typical use cases: offline scans, faster testing, service outages.

---

## NVD API Integration

| | Without API key | With API key |
|---|---|---|
| NVD limit | 5 requests / 30 s | 50 requests / 30 s |
| Delay between requests | 6.5 s | 0.7 s |

Further behavior:

- Up to 3 attempts per CVE with backoff (6 s, 12 s) on 403/429/503/timeouts
- After 5 consecutive failures the version check is aborted (already fetched CVEs stay cached)
- At most 150 new requests per run by default (`-NvdMaxCves`, `-NoNvdLimit`); skipped CVEs are rated "Unclear" and the report says **"Scan incomplete"**
- Only CVE identifiers are sent

```powershell
-NvdApiKey YOUR_API_KEY
# or
$env:CVEWATCH_NVD_API_KEY = 'YOUR_API_KEY'
```

API keys are available free of charge from https://nvd.nist.gov/developers/request-an-api-key

---

## Generated Files

All files are written to `%USERPROFILE%\CVEwatch\assets\<COMPUTERNAME>\` with the name pattern `<COMPUTERNAME>_HHmmss_ddMMyy.<type>`.

| File | Purpose |
|--------|--------|
| `.report.html` | Human-readable report (English and German, switchable, printable) |
| `.csv` | Asset inventory (UTF-8, delimiter `;`, columns Name, Version, Manufacturer, Source, Path, Display) |
| `.matches.json` | Machine-readable findings |
| `.log` | Host summary (in the run language) |
| `.summary.json` | Executive summary data |

### matches.json

One object per matched product: `Product`, `Version`, `Source`, `RansomwareRelated`, `Affected`, `Hits`.

Each hit: `CVE`, `Vendor`, `Product`, `Name`, `Added`, `Due`, `Ransom`, `Desc`, `Action`, `Confidence` (`Hoch`/`Mittel`), `Basis`, `VersionVerdict` (internal key, see table above), `VerdictReason` (`{ "de": …, "en": … }`), `AffectedRanges`, `MatchedRanges`, `FixedIn`, `CvssScore`, `CvssSeverity`, `CvssVersion` (CVSS fields only if the NVD was queried).

### summary.json

`host`, `version`, `lang`, `date`, `rating`, `admin`, `counts` (`critical`, `high`, `medium`, `info`), `findings` (each with a language-independent `severity_key` plus `severity`, `area`, `title`, `detail`, `effort` in the run language), `positives`, `notes`.

For automated evaluation use `severity_key` and `counts`, as the texts depend on `-Lang`.

---

## Automation Support

### Output

At the end of every run the script prints two machine-readable lines:

```text
CVEWATCH_REPORT=<path to report>
CVEWATCH_SUMMARY host=PC01 kev_products=3 open=2 nvd_skipped=0 cve_hits=7 affected=1 overdue=1 ransomware=1 new=0 admin=1 exit=4
```

### Exit codes

| Code | Meaning |
|--------|--------|
| 0 | No open findings (or KEV matching skipped) |
| 1 | Cancelled by the user before the scan (interactive console without admin rights) |
| 2 | KEV hits with open version (not rated as patched) |
| 3 | Overdue CISA due date |
| 4 | Confirmed vulnerable version |
| 5 | Administrator rights missing and `-RequireAdmin` set |

If several apply, the highest-priority code wins: 4 > 3 > 2.

Suitable for:

- Task Scheduler
- Monitoring systems
- Automation workflows
- CI/CD validation

---

## Optional Network Functions

The following features are disabled by default:

```powershell
-PublicIP
-Latency
-SpeedTest
-External
```

### Public IP

Queries `api.ipify.org`, fallback `ifconfig.me`.

### Latency testing

Pings `www.google.de`, fallback `www.devicentra.de` (3 pings, average). The gateway ping is local and always runs.

### Speed test

Downloads a 10 MB test file from `crusadersoft.com` into memory (no disk write, cache buster, timer starts after the response begins). Rating in Mbit/s: Excellent ≥ 50, Good ≥ 20, OK ≥ 10, Poor ≥ 2, otherwise Insufficient. On very fast lines (roughly above 300 Mbit/s) the result is a minimum value.

No inventory data is transmitted.

---

## Languages

- `-Lang en` (default) or `-Lang de` controls the window, the console output, the host log and the texts in `summary.json`.
- The GUI language button rebuilds the window in the other language and passes `-Lang` to the scan process.
- The HTML report always contains both languages. The language of the run is shown first; the switch at the top changes all texts including mouse-over explanations. No network access is involved.
- Internally, values are bilingual objects that behave like the German text in comparisons, so all rules work independently of the display language.

---

## File Encoding and Signing

- The script is saved as **UTF-8 with BOM**. Windows PowerShell 5.1 reads files without BOM as ANSI, which breaks German umlauts; the script warns at start if the BOM is missing. Keep the BOM when editing (VS Code: "Save with Encoding" → "UTF-8 with BOM").
- Recommended `.gitattributes`: `*.ps1 text eol=crlf`
- Authenticode signing is supported like for any PowerShell script (`Set-AuthenticodeSignature`). Any change invalidates the signature; sign last, then publish the SHA256 checksum.

---

## Known Limitations

Transparency matters.

### KEV limitations

The CISA KEV catalog does not contain machine-readable version ranges. Initial detections are product-based; version validation follows through the NVD.

### NVD data

CPE data is not always complete or may not exist yet for new CVEs. Such hits are rated "Unclear" with the reason.

### Vendor versioning

Software vendors do not always use consistent version schemes. Version validation may therefore return "Unclear" even though a KEV relationship exists.

### Windows build check

Depends on the NVD listing build boundaries per Windows release. New releases may not be recorded yet; releases out of support are not checked.

### Network exposure

Whether a listening port is reachable from the internet depends on the Windows firewall and the router; this is not checked.

### False positives

While NVD validation significantly improves accuracy, no automated matching process can completely eliminate false positives.

Critical findings should always be reviewed manually.

---

## Privacy

Everything runs locally.

By default:

- No telemetry
- No cloud dependency
- No software inventory upload
- No user tracking

Only KEV and NVD requests are performed by default; the NVD only receives CVE identifiers. The report lists exactly which outbound connections were made during that run.

The Community Edition does not transmit inventory data to Crusadersoft.

---

## Data Sources

- Known Exploited Vulnerabilities Catalog: CISA, https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- National Vulnerability Database: NIST, https://nvd.nist.gov

This product uses data from the NVD API but is not endorsed or certified by the NVD.
