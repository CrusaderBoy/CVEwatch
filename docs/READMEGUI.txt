## What Does CVEwatch Do?

CVEwatch inventories your Windows device (hardware, installed software, drivers and services) and compares installed software against the CISA Known Exploited Vulnerabilities (KEV) Catalog. It then validates findings against NIST NVD data to determine whether the installed version is actually affected.

The result is a prioritized HTML report focused on vulnerabilities that are actively exploited in the real world.

✅ Local processing

✅ Security posture assessment

✅ KEV intelligence

✅ NVD version validation

✅ HTML reporting

✅ No telemetry

---

<details>
<summary><b>Scan Workflow</b></summary>

1. System & Hardware
2. Security Posture
3. Network Analysis
4. Software Inventory
5. Download KEV Catalog
6. KEV Matching
7. NVD Version Validation
8. HTML Report Generation

Progress is displayed live in the GUI. The scan runs in a separate process and the interface remains responsive.

</details>

<details>
<summary><b>Options</b></summary>

### KEV Matching

Disabled:
- Inventory and security posture only
- No vulnerability correlation

### NVD Version Validation

Disabled:
- Shows only that a product appears in KEV

Enabled:
- Checks whether the installed version is actually vulnerable

### NVD API Key

Optional free API key from NVD.

Rate limits increase from:

- 5 requests / 30 seconds

to:

- 50 requests / 30 seconds

### Cache Mode

Uses locally cached KEV and NVD data.

Useful for:

- Offline operation
- Faster scans
- Temporary source outages

### Optional External Tests

Disabled by default.

```powershell
-PublicIP
-Latency
-SpeedTest
-External
```

</details>

<details>
<summary><b>Security Posture Assessment</b></summary>

Checks include:

- Patch Status
- Secure Boot
- BitLocker
- TPM
- RDP
- SMBv1
- Local Administrators
- Guest Account
- Credential Guard
- VBS / HVCI
- Entra ID / Domain Join
- Listening Ports

### Microsoft Defender

- Engine Version
- Signature Version
- Real-Time Protection
- Tamper Protection
- Cloud Protection
- ASR Rules
- Exclusions
- Last Scans

### Storage

- HDD
- SSD
- NVMe
- USB Storage

Including:

- Health Status
- Capacity
- BitLocker Protection

</details>

<details>
<summary><b>Understanding the Report</b></summary>

Findings are prioritized by:

1. Ransomware Association
2. CISA Remediation Deadline
3. Version Validation Result
4. Match Confidence

### Colors

🔴 Affected / Overdue

🟠 Ransomware Related / Due Soon

🟢 Likely Patched

Findings marked **NEW** were not present during the previous scan.

</details>

<details>
<summary><b>Reports & Automation</b></summary>

Generated outputs:

- HTML Report
- CSV Inventory
- JSON Findings
- Log File
- summary.json

Exit Codes:

| Code | Meaning |
|--------|--------|
| 0 | No findings |
| 2 | KEV findings |
| 3 | Overdue remediation deadline |
| 4 | Confirmed vulnerable version |

Ideal for scheduled tasks and monitoring systems.

</details>

<details>
<summary><b>Privacy & Data Sources</b></summary>

Everything runs locally.

No inventory data is transmitted.

### Default Connections

- CISA KEV Catalog
- NIST NVD

Only CVE identifiers are requested.

### Optional Connections

- api.ipify.org
- ifconfig.me
- www.google.de
- www.devicentra.de
- crusadersoft.com (10 MB speed test)

### Privacy

✅ No telemetry

✅ No inventory upload

✅ No cloud dependency

✅ No software inventory sharing

Reports remain on the local device.

Privacy Policy:

https://crusadersoft.com/#datenschutz

</details>

<details>
<summary><b>Enterprise Features</b></summary>

The Community Edition intentionally scans only the local device.

Enterprise features include:

- FleetScan
- Multi-Report Aggregation
- Central Dashboards
- Historical Tracking
- Fleet Analytics
- Network Discovery
- Network Scanning
- Dedicated CVEwatch Instances

More information:

- https://crusadersoft.com
- https://cvewatch.de

</details>

