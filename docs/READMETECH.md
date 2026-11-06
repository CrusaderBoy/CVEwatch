# Technical Details

## Data Collection

CVEwatch collects information from the local Windows system and combines several inventory sources to build a comprehensive asset inventory.

### System Information

- Operating System
- Windows Build
- BIOS Information
- CPU
- GPU
- Memory
- Storage Devices
- Network Configuration
- Security Configuration

### Software Inventory

Software is collected from multiple sources:

- Installed Programs (Registry)
- Winget Packages
- AppX Packages
- Running Processes
- Windows Services
- Installed Drivers

Combining multiple sources significantly increases software coverage compared to relying on uninstall entries alone.

---

## Vulnerability Detection Workflow

CVEwatch uses a two-stage detection model.

### Stage 1: KEV Correlation

The software inventory is matched against the CISA Known Exploited Vulnerabilities (KEV) Catalog.

Purpose:

> Identify products that are associated with vulnerabilities currently being exploited in real-world attacks.

At this stage, no version validation is performed because the KEV Catalog does not provide machine-readable affected version ranges.

---

### Stage 2: NVD Version Validation

For every KEV match, CVEwatch retrieves vulnerability details from NIST NVD.

The installed version is then compared against the vulnerable version ranges defined in the CVE.

Possible outcomes:

- Affected
- Version Unknown
- Likely Patched

This additional validation significantly reduces false positives.

---

## Matching Heuristics

Product identification relies on multiple matching strategies.

Examples include:

- Product Name Matching
- Vendor Matching
- Combined Product + Vendor Matching
- Normalized Name Comparison

Each result receives a confidence rating:

### High Confidence

Product and vendor successfully matched.

### Medium Confidence

Strong product name correlation.

### Low Confidence

Partial product indication only.

Confidence values remain visible in reports to ensure transparency.

---

## Report Prioritization

Findings are sorted by actual operational risk.

Priority order:

1. Ransomware Association
2. CISA Due Date
3. Version Verdict
4. Match Confidence

This helps focus attention on vulnerabilities most likely to require immediate remediation.

---

## Executive Summary Engine

Every report starts with an Executive Summary.

The Executive Summary evaluates findings and automatically generates:

- Risk Status
- Finding Counts
- Prioritized Recommendations
- Top Remediation Actions

Administrators can customize the underlying rules directly in the source code.

The relevant logic is located in:

```powershell
# EXECUTIVE SUMMARY
```

section of the script.

---

## Caching Strategy

By default:

✅ KEV data is downloaded fresh

✅ NVD data is downloaded fresh

for every scan.

This behavior is intentional.

New actively exploited vulnerabilities can appear at any time.

### Cache Mode

```powershell
-UseCache
```

uses locally stored KEV and NVD data.

Typical use cases:

- Offline Scans
- Faster Testing
- Service Outages

---

## NVD API Integration

Version validation requires access to NVD CVE data.

Without an API key:

```text
5 requests / 30 seconds
```

With an API key:

```text
50 requests / 30 seconds
```

Optional parameter:

```powershell
-NvdApiKey YOUR_API_KEY
```

API keys are available free of charge from:

https://nvd.nist.gov

---

## Generated Files

Each scan generates:

| File | Purpose |
|--------|--------|
| HTML Report | Human-readable report |
| CSV Inventory | Asset inventory |
| JSON Findings | Machine-readable findings |
| Host Log | System summary |
| summary.json | Executive Summary data |

---

## Automation Support

CVEwatch exposes machine-readable status information.

### Output

```text
CVEWATCH_SUMMARY
```

### Exit Codes

| Code | Meaning |
|--------|--------|
| 0 | No findings |
| 2 | KEV findings present |
| 3 | Overdue remediation deadline |
| 4 | Confirmed vulnerable version |

Suitable for:

- Task Scheduler
- Monitoring Systems
- Automation Workflows
- CI/CD Validation

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

Queries:

- api.ipify.org
- ifconfig.me

### Latency Testing

Targets:

- www.google.de
- www.devicentra.de

### Speed Test

Downloads a 10 MB test file from:

- crusadersoft.com

No inventory data is transmitted.

---

## Known Limitations

Transparency matters.

### KEV Limitations

The CISA KEV Catalog does not contain machine-readable version ranges.

For this reason:

- Initial detections are product-based.
- Version validation occurs afterwards through NVD.

### Vendor Versioning

Software vendors do not always use consistent version schemes.

As a result, version validation may occasionally return:

```text
Version Unknown
```

even though a KEV relationship exists.

### False Positives

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

Only KEV and NVD requests are performed by default.

The Community Edition does not transmit inventory data to Crusadersoft.
