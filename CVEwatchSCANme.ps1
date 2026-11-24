<#
================================================================================
  CVEwatch - Asset Scan + KEV Matcher  (Version 4.1)
  ------------------------------------------------------------------------------
  ENGLISH SUMMARY
    Local, agentless vulnerability triage for a single Windows device:
      - collects hardware, storage, OS, network and security posture (Defender, BitLocker, ports ...)
      - inventories installed software (registry, winget, AppX, processes, services, drivers)
      - matches it against the CISA KEV catalog (actively exploited vulnerabilities)
      - checks per hit via the NIST NVD whether the installed version is affected (incl. Windows build)
      - writes an HTML report (German + English, switchable) plus CSV / JSON / LOG / summary.json
    Privacy: everything runs locally, no inventory data is transmitted. By default only the KEV catalog
    and the NVD data for all KEV CVEs (same download for every device, no device-specific data) are
    downloaded; only CVEs the NVD does not mark as KEV yet are requested individually by CVE identifier.
    Public IP, latency and speed test are opt-in (-PublicIP, -Latency, -SpeedTest, -External).
    Run:  powershell -ExecutionPolicy Bypass -File .\CVEwatchSCANme.ps1 -Gui
          powershell -ExecutionPolicy Bypass -File .\CVEwatchSCANme.ps1 -Lang de     (console, German)
    Language: -Lang en (default) or -Lang de; the window has a language button, the report a switch.
    This product uses data from the NVD API but is not endorsed or certified by the NVD.
  ------------------------------------------------------------------------------
  DEUTSCH
  Was das Tool macht:
    1. Erfasst Hardware / Massenspeicher / OS / Netzwerk (inkl. Download-Speedtest) / Security-Status des Geraets
    2. Inventarisiert installierte Software (Registry, Winget, AppX,
       laufende Prozesse, Dienste, Treiber)
    3. Zieht den CISA KEV-Katalog (Known Exploited Vulnerabilities)
    4. Gleicht das Inventar per Name-/Vendor-Matching mit KEV ab
       -> "Diese Produkte bei dir tauchen in aktiv ausgenutzten CVEs auf"
    5. Vergleicht die Treffer mit betroffenen Versionsnummern (NVD)
       -> "Pro Treffer werden wir einen Call zur NVD durchführen (6 sek Standard)"
    6. Erzeugt einen HTML-Report und oeffnet ihn im Browser
    7. Schreibt zusaetzlich CSV (Inventar) + JSON (Matches) + LOG (Host)
       + summary.json (Management-Befunde nach Schweregrad)
    8. Der Report beginnt mit einer Management-Uebersicht (Ampel, Befunde nach Schweregrad,
       Top-Massnahmen). Die Regeln dafuer stehen im Block EXECUTIVE SUMMARY und sind anpassbar.

  WICHTIG / EHRLICHE GRENZEN dieser Version:
    - Der Abgleich erfolgt zweistufig:
      1. Produkt-/Hersteller-Matching gegen den CISA KEV-Katalog
         -> "Dieses Produkt taucht in aktiv ausgenutzten CVEs auf"
      2. Versionsabgleich pro Treffer
         -> Für jeden Match wird die betroffene Versionsinformation aus der NVD
            abgefragt und mit der lokal installierten Version verglichen.

    - KEV liefert keine maschinenlesbaren Versionsbereiche.
      Der erste Treffer basiert daher weiterhin auf dem Produkt- Namen und Hersteller.
      Erst danach wird über die NVD geprüft, ob die installierte Version
      innerhalb der betroffenen Range liegt.

    - Ein KEV-Treffer bedeutet :
        -> "Dieses Produkt ist in KEV vertreten"
        -> "Wir haben geprüft, ob deine Version verwundbar ist"
      Der Report zeigt beide Informationen getrennt und klar verständlich.

    - Match-Konfidenz bleibt bestehen (Hoch/Mittel/Niedrig),
      damit False Positives aus dem Produkt-Matching weiterhin sichtbar bleiben.

    - Datenschutz: Alles läuft lokal. Es werden keine Inventardaten übertragen. Standardmäßig
      gehen nur zwei Abrufe nach außen (die Gegenstelle sieht dabei deine IP-Adresse):
        -> Abruf des CISA-KEV-Katalogs
        -> Abruf der NVD-Daten zu allen KEV-CVEs (gleicher Abruf für jedes Gerät, nichts Gerätespezifisches);
           nur CVEs, die die NVD noch nicht als KEV führt, werden einzeln per CVE-Kennung abgefragt
      Weitere Verbindungen sind OPT-IN (Standard: aus), jeweils einzeln schaltbar:
        -> -PublicIP  : Ermittlung der öffentlichen IP (api.ipify.org / ifconfig.me, Drittanbieter)
        -> -Latency   : Ping an www.google.de / www.devicentra.de
        -> -SpeedTest : 10-MB-Testdatei von crusadersoft.com (es wird nichts hochgeladen)
        -> -External  : Kurzform für alle drei
      Der Report enthält personenbezogene Daten (Hostname, Benutzerkonten, IP/MAC): nur an
      Berechtigte weitergeben. Datenschutzerklärung: https://crusadersoft.com/#datenschutz

  Ausführen:
      powershell -ExecutionPolicy Bypass -File .\CVEwatchSCANme.ps1
      powershell -ExecutionPolicy Bypass -File .\CVEwatchSCANme.ps1 -Gui   (grafische Oberfläche)
  (Admin ist nicht zwingend, liefert aber vollständigere Treiber-/Dienstdaten.)
  GUI und Konsole weisen vor dem Scan darauf hin, wenn sie ohne Administratorrechte laufen:
  die GUI bietet den Neustart als Administrator an. Die Konsole wartet in einer echten, interaktiven
  Sitzung 10 Sekunden (Taste N = abbrechen) und startet dann von selbst - sie blockiert nie.
  Für Rollouts: -AllowNonAdmin = still weiterlaufen, -RequireAdmin = sofort Exit-Code 5.
  Als SYSTEM (Intune/SCCM): Ablage unter %ProgramData%\CVEwatch\assets, -NoOpen setzen. Aus einer
  32-Bit-PowerShell startet sich das Skript selbst in der 64-Bit-PowerShell neu (sonst fehlen 64-Bit-Programme).

  Änderungen 4.1: (Beitrag: Ariazonaa, PR #1):
    - NVD-Sammelabruf: Die NVD-Daten zu allen KEV-CVEs werden gesammelt geholt (cves/2.0?hasKev, wenige Seiten),
      danach nur noch Änderungen seit dem letzten Lauf (lastModStartDate). Alle 30 Tage bzw. nach mehr als
      119 Tagen Pause wird komplett neu geladen. Ohne API-Key entfällt damit die lange Wartezeit pro CVE, das
      150er-Limit greift nur noch für Einzelabfragen (CVEs, die die NVD noch nicht als KEV markiert hat).
      Datenschutz: Der Sammelabruf ist für jedes Gerät gleich und verrät nicht, welche Software installiert ist.
    - Nachgetragene Windows-Releases und korrigierte Build-Grenzen kommen über den Änderungsabgleich sofort an,
      statt bis zu 30 Tage im Cache zu hängen.
    - GUI: Fortschrittsbalken und Statuszeile laufen beim NVD-Sammelabruf mit; Versionsnummer im Fenster und im Fenstertitel.
    - NVD-Cache kompakter gespeichert (Bereiche als Text), damit Laden/Speichern auch in PowerShell 5.1 schnell bleibt.
      Neuer Dateiname nvd_cache_v2.json (ältere Versionen würden das kompakte Format sonst als "keine NVD-Daten"
      lesen); die alte nvd_cpe_cache.json wird beim ersten Lauf übernommen und danach nicht mehr verändert.

  Änderungen 4.0.1 (Beitrag: Ariazonaa, PR #1):
    - Windows-Build-Abgleich: Fehlt das eigene Windows-Release bei einer CVE in der NVD, werden die Build-Grenzen
      eines Schwester-Release aus demselben Wartungszweig übernommen (z. B. 24H2/25H2/26H2, 22H2/23H2,
      Windows 10 2004-22H2). Der Report kennzeichnet solche Verdikte als "Abgeleitet".
    - Versionsteile als Int64: lange Datums-/Build-Stempel führen nicht mehr zu Laufzeitfehlern.
================================================================================
#>

param(
    [switch] $Gui,             # grafische Oberfläche starten (kapselt den Kern-Flow als Kindprozess)
    [switch] $AllowNonAdmin,   # Rollout/Automatisierung: ohne Administratorrechte still weiterlaufen (Warnung nur im Log)
    [switch] $RequireAdmin,    # Rollout/Automatisierung: ohne Administratorrechte sofort mit Exit-Code 5 beenden
    [switch] $NoOpen,          # Report am Ende NICHT automatisch öffnen (GUI setzt das)
    [switch] $NoKev,           # KEV-Abgleich überspringen -> nur Geräte-Inventar + Sicherheits-Posture
    [switch] $NoVersionCheck,  # NVD-Versionsabgleich überspringen (KEV läuft weiter)
    [switch] $NoOsCheck,       # Windows-Build-Abgleich (KEV-Einträge zu Windows selbst, per NVD) überspringen
    [int]    $NvdMaxCves = 150, # Höchstzahl NEUER NVD-Abfragen pro Lauf (Cache-Treffer zählen nicht); der Rest bleibt "unvollständig" und wird beim nächsten Lauf nachgeholt
    [switch] $NoNvdLimit,       # kein Limit: alle CVEs in einem Lauf prüfen (dauert ohne API-Key deutlich länger)
    [switch] $OsAllYears,      # Build-Abgleich auch für KEV-Einträge, die älter sind als das installierte Windows-Release (mehr NVD-Abfragen)
    [switch] $PublicIP,        # OPT-IN: öffentliche IP ermitteln (Anfrage an api.ipify.org bzw. ifconfig.me)
    [switch] $Latency,         # OPT-IN: Internet-Latenz messen (Ping an www.google.de bzw. www.devicentra.de)
    [switch] $SpeedTest,       # OPT-IN: Download-Speedtest (10-MB-Testdatei von crusadersoft.com)
    [switch] $External,        # Kurzform: alle drei Tests nach außen aktivieren
    [switch] $UseCache,        # KEV UND NVD aus lokalem Cache nehmen statt frisch zu laden (schnell/offline)
    [string] $NvdApiKey = '',  # optionaler NVD-API-Key -> höheres Rate-Limit
    [string] $StatusFile = '', # (intern) Fortschritt für die GUI in diese Datei schreiben
    [ValidateSet('en','de')]
    [string] $Lang = 'en'      # Sprache von Oberfläche, Konsole und Standardsprache des Reports (der Report enthält immer DE + EN)
)

$ErrorActionPreference = 'Continue'

# 32-Bit-PowerShell auf 64-Bit-Windows (z. B. Intune-Plattformskript ohne "64-Bit-Host", Win32-App ohne sysnative):
# Windows leitet dann HKLM:\Software auf WOW6432Node um -> 64-Bit-Programme wären unsichtbar (falsch-negative KEV-Ergebnisse).
# Deshalb in der 64-Bit-PowerShell neu starten und deren Exit-Code durchreichen. Der API-Key geht über die Umgebung
# (CVEWATCH_NVD_API_KEY) statt über die Kommandozeile, damit er nicht in der Prozessliste steht.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and $PSCommandPath) {
    $ps64 = Join-Path $env:WINDIR 'sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        if ($NvdApiKey) { $env:CVEWATCH_NVD_API_KEY = $NvdApiKey }
        $fwd = @(foreach ($k in $PSBoundParameters.Keys) {
            if ($k -eq 'NvdApiKey') { continue }
            $v = $PSBoundParameters[$k]
            if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { "-$k" } } else { "-$k"; "$v" }
        })
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @fwd
        exit $LASTEXITCODE
    }
}

$ProgressPreference     = 'SilentlyContinue'   # unterdrückt langsame Fortschrittsbalken
$ScriptVersion          = '4.1'                 # EINZIGE Stelle für die Versionsnummer (Report-Fußzeile, summary.json)

# ---------------------------------------------------------------------------
# SPRACHE / LANGUAGE
#   G 'de' 'en'  -> Text in der aktuellen Sprache (GUI, Konsole, Logs)
#   L 'de' 'en'  -> zweisprachiger WERT: verhält sich in Vergleichen und Strings wie der deutsche Text
#                   (interne Logik bleibt unverändert), der Report zeigt beide Sprachen (siehe V/B)
#   LT $wert     -> Wert in der aktuellen Sprache als Text
# ---------------------------------------------------------------------------
$script:Lang = $Lang
function G([string]$de, [string]$en) { if ($script:Lang -eq 'de') { $de } else { $en } }
function L([string]$de, [string]$en) {
    $o = [pscustomobject]@{ de = $de; en = $en }
    $o | Add-Member -MemberType ScriptMethod -Name ToString -Value { $this.de } -Force
    $o
}
function Test-L($v) { return ($null -ne $v -and $v -isnot [string] -and $v.PSObject.Properties['de'] -and $v.PSObject.Properties['en']) }
function LT($v) { if (Test-L $v) { if ($script:Lang -eq 'de') { $v.de } else { $v.en } } else { "$v" } }
function LT2($v, [string]$In) { if (Test-L $v) { $v.$In } else { "$v" } }

# Windows PowerShell 5.1 liest .ps1-Dateien ohne BOM als ANSI -> Umlaute in GUI, Konsole und Report wären kaputt.
# Die Datei muss daher als "UTF-8 mit BOM" gespeichert sein; sonst hier deutlich warnen.
if ($PSVersionTable.PSVersion.Major -lt 6 -and $PSCommandPath) {
    try {
        $fs = [System.IO.File]::OpenRead($PSCommandPath); $bom = New-Object byte[] 3; [void]$fs.Read($bom, 0, 3); $fs.Close()
        if (-not ($bom[0] -eq 0xEF -and $bom[1] -eq 0xBB -and $bom[2] -eq 0xBF)) {
            Write-Warning (G 'Diese Skriptdatei ist nicht als UTF-8 mit BOM gespeichert. Umlaute werden falsch angezeigt. Bitte die Originaldatei neu herunterladen oder im Editor als "UTF-8 mit BOM" speichern.' 'This script file is not saved as UTF-8 with BOM. German umlauts will be displayed incorrectly. Please download the original file again or save it as "UTF-8 with BOM" in your editor.')
        }
    } catch {}
}

$MAINiconBase64Icon = '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'
$MAINiconBytes      = [Convert]::FromBase64String($MAINiconBase64Icon)
$MAINiconstream     = [System.IO.MemoryStream]::new($MAINiconBytes, 0, $MAINiconBytes.Length)

$MAINlogoBase64Icon = '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'
$MAINlogoBytes      = [Convert]::FromBase64String($MAINlogoBase64Icon)
$MAINlogostream     = [System.IO.MemoryStream]::new($MAINlogoBytes, 0, $MAINlogoBytes.Length)
# Datenstrom vor jedem Lesen auf den Anfang setzen (das Fenster wird beim Sprachwechsel neu aufgebaut und liest Icon/Logo erneut)
function Reset-Stream($st) { $st.Position = 0; return ,$st }

# TLS 1.2 für PS 5.1 erzwingen (sonst schlägt der HTTPS-Abruf oft fehl)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

#region ================================ GUI =================================
# Grafische Oberfläche: erklärt den Ablauf und startet den KERN-Flow als
# Kindprozess (dieses Skript ohne -Gui, mit -NoOpen). Dadurch bleibt der
# eigentliche Scan unverändert verteilbar; die GUI ist nur ein Aufsatz.

# Hilfe-/Anleitungsfenster: erklärt alle Features. In eigener Funktion, damit die
# WinForms-Typen erst beim Aufruf aufgelöst werden (Headless-Flow bleibt unberührt).
function Show-CVEwatchHelp($cBg, $cSurf, $cSurf2, $cText, $cMut, $cBlue) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Zusatzfarben für die Hilfe (passend zum dunklen Thema)
    $cLine  = [System.Drawing.Color]::FromArgb(48, 54, 61)      # feine Trennlinien
    $cCode  = [System.Drawing.Color]::FromArgb(232, 176, 88)    # Parameter, Befehle, Dateinamen
    $cTeal  = [System.Drawing.Color]::FromArgb(86, 196, 184)    # Zwischenüberschriften
    $cAmb   = [System.Drawing.Color]::FromArgb(240, 160, 32)    # "Keine Treffer"
    $cHit   = [System.Drawing.Color]::FromArgb(92, 76, 18)      # Suchtreffer
    $cCur   = [System.Drawing.Color]::FromArgb(31, 111, 235)    # aktueller Suchtreffer
    $cHover = [System.Drawing.Color]::FromArgb(30, 36, 44)      # Inhaltsverzeichnis: Maus darüber

    $fH    = New-Object System.Drawing.Font('Segoe UI', 15, [System.Drawing.FontStyle]::Bold)
    $fB    = New-Object System.Drawing.Font('Segoe UI', 10)
    $fBold = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $fSub  = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $fMono = New-Object System.Drawing.Font('Consolas', 10)
    $fGap  = New-Object System.Drawing.Font('Segoe UI', 5)
    $fNav  = New-Object System.Drawing.Font('Segoe UI', 9.5)
    $fNavOn = New-Object System.Drawing.Font('Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold)

    # ---------------------------------------------------------------- Inhalt (Abschnitte werden erst gesammelt, dann gezeichnet)
    $secs = New-Object System.Collections.ArrayList
    function AddSec($t, $b) { [void]$secs.Add([pscustomobject]@{ T = [string]$t; B = [string]$b }) }

    $sn = if ($PSCommandPath) { Split-Path $PSCommandPath -Leaf } else { 'CVEwatchSCANme.ps1' }   # echter Dateiname für die Beispiele unten

    if ($script:Lang -eq 'de') {
    AddSec 'Schnellstart (Kurzfassung)' `
'1. Unten auf "Scan starten" klicken - am besten als Administrator, dann sind die Ergebnisse vollständiger (die Oberfläche bietet den Neustart an).
2. Warten, bis links alle Stufen grün sind. Beim ersten Mal kann der NVD-Abgleich einige Minuten dauern (die NVD begrenzt die Abfragen, das ist normal und kein Hänger; mit einem kostenlosen NVD API-Key geht es etwa zehnmal schneller).
3. Der Report öffnet sich im Browser. Von oben nach unten lesen: erst die Management-Übersicht, dann die KEV-Treffer. Rot und weit oben = zuerst kümmern.
Mehr brauchst du am Anfang nicht. Alles Weitere unten sind Feineinstellungen, die du nach und nach entdecken kannst.'

    AddSec 'Der Ablauf (Stufen links)' `
'1. System + Hardware
2. Sicherheits-Posture
3. Netzwerk
4. Software-Inventar
5. KEV-Katalog laden
6. KEV-Abgleich
7. NVD-Versionsabgleich
8. HTML-Report
Der Fortschritt wird links live angezeigt; der Scan läuft als eigener Prozess, das Fenster bleibt bedienbar.'

    AddSec 'Optionen und ihre Parameter' `
'• KEV-Abgleich: aktiv ausgenutzte Lücken finden (Standard: an). Aus = nur Geräte-Inventar und Sicherheits-Posture, kein Schwachstellen-Abgleich. Kommandozeile: -NoKev
• + NVD-Versionsabgleich (Version betroffen?) (Standard: an). Prüft anhand der NVD, ob deine installierte Version im verwundbaren Bereich liegt, und holt den CVSS-Schweregrad. Die NVD-Daten zu allen KEV-CVEs werden gesammelt geladen (wenige Anfragen), danach nur noch Änderungen. Aus = nur "Produkt ist in KEV", ohne Versionsprüfung. Kommandozeile: -NoVersionCheck
• + Windows-Build prüfen (Standard: an, nur zusammen mit dem NVD-Versionsabgleich): Vergleicht deinen exakten Windows-Build mit den KEV-Einträgen zu Windows selbst und sagt, welche Lücken dein Build noch hat und ab welchem Build sie behoben sind. Kostet zusätzliche NVD-Abfragen; ohne API-Key dauert der erste Lauf deutlich länger, danach hilft der Cache. Kommandozeile: -NoOsCheck (zusätzlich -OsAllYears: auch Einträge, die älter als dein Windows-Release sind)
• NVD API-Key (optional): kostenlos bei nvd.nist.gov. Hebt das Limit von 5 auf 50 Anfragen je 30 Sekunden - der Versionsabgleich wird deutlich schneller und zuverlässiger. Kommandozeile: -NvdApiKey oder die Umgebungsvariable CVEWATCH_NVD_API_KEY
• NVD-Limit (Standard: an, 150 neue Abfragen pro Lauf): Greift nur noch für Einzelabfragen - also CVEs, die der Sammelabruf nicht abdeckt (z. B. ganz neu im KEV, von der NVD noch nicht markiert) oder wenn der Sammelabruf fehlschlägt. Begrenzt, wie viele CVEs ein Lauf einzeln neu bei der NVD abfragt; bereits gespeicherte zählen nicht. Reicht das Limit nicht, sagt der Report oben deutlich "Scan unvollständig", und du musst erneut scannen: Der zweite Lauf holt die fehlenden CVEs nach. Ohne Limit (Haken entfernen) wird alles in einem Lauf geprüft, ohne API-Key dauert das lange. Kommandozeile: -NvdMaxCves ZAHL oder -NoNvdLimit
• Cache verwenden statt frisch laden (Standard: aus). Siehe "Aktualität & Cache". Kommandozeile: -UseCache
• Verbindungen nach außen (alle standardmäßig AUS, einzeln schaltbar): Öffentliche IP ermitteln (-PublicIP), Internet-Latenz messen (-Latency), Download-Speedtest (-SpeedTest); alle drei zusammen: -External. Details unter "Datenschutz & Quellen".
• Sprache: Der Knopf "Deutsch" / "English" oben schaltet das Fenster und die Konsolenausgabe des Scans um. Der HTML-Report enthält immer beide Sprachen und hat einen eigenen Umschalter. Kommandozeile: -Lang de oder -Lang en (Standard: en)'

    AddSec 'Aktualität & Cache' `
'Standard ist bewusst: KEV UND NVD werden bei JEDEM Lauf frisch geladen - denn jederzeit kann eine neue, gerade ausgenutzte CVE dazukommen. "Cache verwenden" ist die schnelle bzw. offline-Option: KEV und NVD-Angaben kommen aus dem lokalen Zwischenspeicher (NVD-Einträge, die älter als 30 Tage sind, werden trotzdem neu geholt). Der Preis: Neu aufgenommene Schwachstellen fehlen (NVD-Angaben zu CVEs, die schon länger als 120 Tage im KEV stehen, dürfen auch ohne diese Option aus dem Cache kommen, damit Folgeläufe schnell sind; im Skriptkopf einstellbar), und NVD-Angaben, die noch ohne Schweregrad (CVSS) gespeichert wurden, bekommen ihn erst nach einem Lauf ohne Cache. Ohne diese Option dient der Cache nur als Ausfall-Netz, falls CISA/NVD kurz nicht erreichbar sind. NVD-Sammelabruf: Der erste Lauf lädt die NVD-Daten aller KEV-CVEs, jeder weitere nur die Änderungen seit dem letzten Lauf; alle 30 Tage (oder nach mehr als 119 Tagen Pause) wird komplett neu geladen (Stand in nvd_kev_sync.json). Die Cache-Dateien (kev_catalog.json, nvd_cache_v2.json, nvd_kev_sync.json) liegen unter %USERPROFILE%\CVEwatch\assets und können jederzeit gelöscht werden.'

    AddSec 'Kommandozeile & Parameter' `
('Für Fortgeschrittene und zur Automatisierung. Die Oberfläche ist nur eine Bedienhilfe: Sie startet dasselbe Skript als eigenen Prozess mit passenden Parametern. Wer lieber die Konsole nutzt oder den Scan automatisieren will (geplanter Task, Rollout), ruft das Skript direkt auf - im Ordner des Skripts, in PowerShell:

powershell -ExecutionPolicy Bypass -File .\{SKRIPT} [Parameter]

Ohne Parameter läuft der Scan direkt in der Konsole und öffnet am Ende den Report. Alle Parameter sind Schalter (einfach anhängen); nur -NvdApiKey, -NvdMaxCves und -Lang bekommen einen Wert.

OBERFLÄCHE UND AUSGABE
• -Gui: startet diese grafische Oberfläche statt eines Konsolenlaufs.
• -NoOpen: öffnet den Report am Ende NICHT automatisch (die Oberfläche nutzt das und öffnet ihn selbst; sinnvoll für Automatisierung).
• -Lang de|en: Sprache von Fenster und Konsole (Standard: en). Der Report enthält immer beide Sprachen.

UMFANG UND AKTUALITÄT
• -NoKev: überspringt den KEV-Abgleich - nur Inventar und Posture.
• -NoVersionCheck: überspringt nur den NVD-Versionsabgleich. Der KEV-Abgleich läuft weiter; es gibt dann aber weder Versionsbereiche noch CVSS-Werte und auch keinen Windows-Build-Abgleich.
• -NoOsCheck: überspringt nur den Windows-Build-Abgleich (KEV-Einträge zu Windows selbst). Spart NVD-Abfragen.
• -OsAllYears: prüft beim Build-Abgleich auch KEV-Einträge, die älter sind als dein Windows-Release (Standard: übersprungen, spart Abfragen; mehr NVD-Zeit).
• -UseCache: KEV und NVD aus dem lokalen Zwischenspeicher statt frisch laden (schnell, auch offline).
• -NvdApiKey SCHLÜSSEL: nutzt einen NVD-API-Key (schneller). Sicherer ist die Umgebungsvariable CVEWATCH_NVD_API_KEY, weil Kommandozeilen-Argumente in der Prozessliste für andere sichtbar sind (die Oberfläche übergibt den Key deshalb ebenfalls per Umgebungsvariable).

VERBINDUNGEN NACH AUSSEN (alle standardmäßig aus)
• -PublicIP: öffentliche IP ermitteln.
• -Latency: Internet-Latenz messen.
• -SpeedTest: Download-Speedtest.
• -External: Kurzform für alle drei.

ADMINISTRATORRECHTE
• Ohne diese Schalter wartet die Konsole in einer interaktiven Sitzung ohne Administratorrechte 10 Sekunden (Taste N = abbrechen) und startet dann von selbst - sie blockiert nie.
• -AllowNonAdmin: ohne Administratorrechte still weiterlaufen (Warnung nur im Log) - für Rollouts.
• -RequireAdmin: ohne Administratorrechte sofort mit Exit-Code 5 beenden, ohne zu scannen.

INTERN
• -StatusFile: Fortschrittsdatei für die Oberfläche - nicht von Hand setzen.

BEISPIELE
• Oberfläche:  powershell -ExecutionPolicy Bypass -File .\{SKRIPT} -Gui
• Schneller Lauf ohne Browser:  ... -File .\{SKRIPT} -UseCache -NoOpen
• Alles inklusive Netzwerktests:  ... -File .\{SKRIPT} -External
• Geplanter Task, der nur per Exit-Code meldet:  ... -File .\{SKRIPT} -RequireAdmin -NoOpen').Replace('{SKRIPT}', $sn)

    AddSec 'Den Report lesen' `
'Produkte und CVEs sind nach echter Dringlichkeit sortiert: Ransomware-Bezug -> CISA-Frist (überfällig zuerst) -> Versions-Verdikt (betroffen > unklar > vermutlich gepatcht) -> Match-Konfidenz -> CVSS-Wert. Jedes Produkt ist eine Karte zum Aufklappen; darin steht pro CVE eine Zeile mit:
• CVE: die Kennung (Klick öffnet die NVD-Seite mit allen Details, z. B. Referenzen und Patch-Links) und - sofern die NVD abgefragt wurde - der CVSS-Schweregrad (Kritisch, Hoch, Mittel, Niedrig) mit Punktwert. Ein orangefarbener Punkt hinter der Kennung = bekannter Ransomware-Bezug.
• Zuordnung & Version: Konfidenz + Basis zeigen, wie sicher die Zuordnung zum KEV-Produkt ist (Produkt+Hersteller vs. nur Produktname). Darunter: "Installiert" = deine Version. "Betroffen" = die verwundbaren Versionsbereiche laut NVD; der Bereich, in dem DEINE Version liegt, ist rot markiert (z. B. "≥ 2.0 und < 2.4.1" heißt: ab 2.0 bis vor 2.4.1). "Behoben" = ab welcher Version die Lücke geschlossen ist. Das Verdikt fasst zusammen: Betroffen, Vermutlich gepatcht oder Unklar - bei Unklar steht dabei, woran es liegt (z. B. keine auswertbare Version im Inventar, NVD ohne Antwort).
• CISA-Frist: bis wann US-Behörden die Lücke schließen müssen - ein guter Maßstab für die eigene Dringlichkeit.
• Schwachstelle: Name, Beschreibung der CVE (Englisch, von CISA; lange Texte sind gekürzt und per "mehr" aufklappbar) und die empfohlene Maßnahme (kursiv).
• Windows selbst: Der Bericht vergleicht deinen Windows-Build (z. B. 10.0.26100.1234) mit den KEV-Einträgen zu Windows. Die NVD nennt je Release die erste Build-Nummer, ab der die Lücke behoben ist. Das Verdikt lautet Betroffen, Vermutlich gepatcht oder Unklar (die NVD nennt dann keine Build-Grenze); bei "Behoben" steht die Build-Nummer. Einträge, die nur andere Windows-Releases betreffen, werden nur gezählt (Management-Übersicht).
• Treffer mit Verdikt "Vermutlich gepatcht" sind je Produkt eingeklappt (Schaltzeile in der Tabelle; beim Drucken sichtbar).
• Chrome und Edge: Chromium-Einträge im KEV gelten für beide. Bei Edge nutzt der Bericht die Versionsbereiche der NVD, sofern sie Edge nennt; sonst wird aus der Hauptversion geschlossen (Edge 152 basiert auf Chromium 152). Eine höhere Hauptversion als die des Fixes zählt als gepatcht, eine niedrigere als betroffen, dieselbe als unklar. Der Grund steht im Bericht ("Abgeleitet: ...").
• Erklärungen per Maus: Fachbegriffe (CVE, KEV, CVSS, Konfidenz, Verdikt, Frist, Ransomware ...) und Tabellenköpfe haben eine Erklärung, die beim Darüberfahren erscheint.
• Lauschende Ports: Der Bericht zeigt, welche Ports von außen erreichbar sind, und ordnet sie ein: grün = normaler Windows-Dienst (z. B. 135, 445, dynamische RPC-Ports, vom erwarteten Prozess), blau = bekannter Dienst, orange = Fernzugriff (RDP, SSH, VNC) oder ungewöhnlicher Prozess auf einem Standardport, rot = veraltet bzw. unverschlüsselt (Telnet, FTP). Grün heißt nicht "sicher", sondern "erwartet". Die Einordnung steht per Maus-Hinweis an jeder Zeile.
• Scan unvollständig: Erscheint oben im Bericht ein oranger Hinweis, fehlen noch CVEs, weil das NVD-Limit erreicht war. Den Scan einfach erneut starten (der Cache spart Zeit) oder das NVD-Limit abschalten.
• Sprache: Der Knopf "Deutsch / English" oben im Bericht schaltet den ganzen Bericht um.
• Aussagekraft dieses Scans (Management-Übersicht): Hier steht, was der Bericht NICHT oder nur eingeschränkt prüft, z. B. Windows, wenn der Build-Abgleich aus ist oder das Release nicht mehr unterstützt wird, die Versionsprüfung von Microsoft-365-Apps (die NVD nennt dort keine Build-Grenzen; angezeigt werden Version und Update-Status), Chromium-Browser außer Chrome und Edge (Brave, Vivaldi, Opera) oder CVEs, die wegen der Obergrenze nicht gegen die NVD geprüft wurden. "Keine Treffer" heißt immer nur: keine Treffer im geprüften Umfang.
Farben: rot = betroffen/überfällig, orange = fällig bald/Ransomware, grün = vermutlich gepatcht. Treffer mit grünem Verdikt "Vermutlich gepatcht" zählen weder für Frist noch Ransomware-Warnung noch für den Exit-Code. Ein grünes NEU markiert Treffer, die seit dem letzten Lauf dazugekommen sind. Bewusst OHNE EPSS - bei KEV ist die Ausnutzung bereits bestätigt, eine Wahrscheinlichkeit wäre daneben redundant.'

    AddSec 'Drucken & Weitergeben' `
'Der Bericht beginnt mit einer Management-Übersicht (Ampel, Befunde nach Schweregrad, die wichtigsten Maßnahmen). Oben im Bericht gibt es Knöpfe: nur die Übersicht oder den ganzen Bericht drucken - im Druckdialog des Browsers dann "Als PDF speichern" wählen. Das Inventar im Bericht ist per Suchfeld durchsuchbar (Name, Version, Hersteller; mehrere Begriffe möglich, Filter nach Quelle wie Registry oder AppX) - das funktioniert direkt im Browser, auch offline. Der Bericht enthält personenbezogene Daten (Hostname, Benutzerkonten, IP/MAC, installierte Software): nur an Berechtigte weitergeben und nach Gebrauch löschen.'

    AddSec 'Sicherheits-Posture' `
'Zusätzlich zum Schwachstellen-Abgleich: Patch-Stand, ausstehender Neustart, Support-Status des Betriebssystems, Secure Boot, BitLocker, TPM, RDP, SMBv1, UAC, registrierte Antivirus-Produkte, lokale Administratoren, Gast-Konto, Autologon, SMB-Freigaben, LSA-Schutz, Virtualisierungsbasierte Sicherheit/HVCI, Credential Guard, NTLM-Level, Geräte-Einbindung (Entra ID/Domäne) und offene (lauschende) Ports. Dazu ein eigener Defender-Block (Produkt-, Engine- und Signaturversion, Echtzeit-, Manipulations-, Cloud-, PUA- und Netzwerkschutz, ASR-Regeln, Ausschlüsse, letzte Scans). Der Massenspeicher-Abschnitt zeigt alle Datenträger (HDD/SSD/NVMe/USB) mit Zustand, Belegung und BitLocker-Status. Riskante Zustände werden rot, Hinweise orange hervorgehoben.'

    AddSec 'Exporte & Automatisierung' `
'Jeder Lauf erzeugt mehrere Dateien unter %USERPROFILE%\CVEwatch\assets\<Computername> (als SYSTEM, z. B. per Intune: %ProgramData%\CVEwatch\assets\<Computername>) - vier davon sind unten im Fenster per Knopf zu öffnen (immer der neueste, nur klickbar wenn vorhanden): Report (HTML, lesbar), Inventar (CSV), Treffer (JSON, maschinenlesbar), Log (Host-Zusammenfassung); dazu eine summary.json mit den Management-Befunden nach Schweregrad. Das Treffer-JSON enthält je CVE auch die Beschreibung, den CVSS-Wert, die betroffenen Versionsbereiche, den Fix-Hinweis und die Begründung des Verdikts - praktisch für eigene Auswertungen. Die Schalter für Automatisierung stehen unter "Kommandozeile & Parameter"; die Konsole blockiert nie auf eine Eingabe. Das Skript gibt eine CVEWATCH_SUMMARY-Zeile (inkl. admin=0/1) und einen Exit-Code aus: 0 = sauber, 2 = KEV-Treffer mit offener Version (nicht als gepatcht eingestuft), 3 = überfällige Frist, 4 = Version betroffen (5 = Administratorrechte fehlen bei -RequireAdmin). Ideal für einen geplanten Task, der nur meldet, wenn es brennt.'

    AddSec 'Datenschutz & Quellen' `
'Alles läuft lokal; es werden keine Inventardaten übertragen. Standardmäßig gehen nur zwei Abrufe nach außen: der KEV-Katalog (CISA, cisa.gov) und die NVD-Daten zu allen KEV-CVEs (NIST NVD, nvd.nist.gov) - dieser Abruf ist für jedes Gerät gleich und verrät nicht, welche Software installiert ist; nur CVEs, die die NVD noch nicht als KEV führt, werden einzeln per CVE-Kennung abgefragt. CISA und NIST sehen deine IP-Adresse. Öffentliche IP, Latenzmessung und Speedtest sind Opt-in (Standard: aus): Die IP-Abfrage geht an api.ipify.org bzw. ifconfig.me, die Latenzmessung pingt www.google.de bzw. www.devicentra.de, der Speedtest lädt 10 MB von crusadersoft.com (es wird nichts hochgeladen); die jeweilige Gegenstelle sieht dabei deine IP-Adresse. Keine Telemetrie, keine Weitergabe deiner Softwareliste. Bericht und Exporte bleiben auf diesem Rechner und enthalten personenbezogene Daten (z. B. Hostname, Benutzerkonten, IP/MAC): nur an Berechtigte weitergeben. Datenschutzerklärung: https://crusadersoft.com/#datenschutz
Dieses Produkt nutzt Daten der NVD-API, ist aber von der NVD weder empfohlen noch zertifiziert (This product uses data from the NVD API but is not endorsed or certified by the NVD).'

    AddSec 'Enterprise' `
'Diese kostenlose Version scannt bewusst nur das lokale Gerät. Die Multi-Report-Auswertung (mehrere Berichte zusammenführen), der FleetScan (viele Hosts) und der Netzwerkscan sind der Enterprise-Version vorbehalten - auch aus Sicherheitsgründen, damit nicht jeder beliebige Netzwerke scannen kann. Mehr unter crusadersoft.com und cvewatch.de.'
    } else {
    AddSec 'Quick start (summary)' `
'1. Click "Start scan" at the bottom - preferably as administrator, the results are then more complete (the window offers to restart elevated).
2. Wait until all stages on the left are green. The first time, the NVD check can take a few minutes (the NVD rate-limits requests; that is normal and not a hang - with a free NVD API key it is about ten times faster).
3. The report opens in your browser. Read it top to bottom: first the management summary, then the KEV hits. Red and near the top = deal with it first.
That is all you need at the beginning. Everything below are fine-tuning options you can discover over time.'

    AddSec 'The process (stages on the left)' `
'1. System + hardware
2. Security posture
3. Network
4. Software inventory
5. Load KEV catalog
6. KEV matching
7. NVD version check
8. HTML report
Progress is shown live on the left; the scan runs as a separate process, so the window stays responsive.'

    AddSec 'Options and their parameters' `
'• KEV matching: find actively exploited vulnerabilities (default: on). Off = device inventory and security posture only, no vulnerability matching. Command line: -NoKev
• + NVD version check (is my version affected?) (default: on). Checks against the NVD whether your installed version is in the vulnerable range and fetches the CVSS severity. The NVD data of all KEV CVEs is downloaded in bulk (few requests), afterwards only changes. Off = only "product is listed in KEV", without version check. Command line: -NoVersionCheck
• + Check Windows build (default: on, only together with the NVD version check): Compares your exact Windows build with the KEV entries for Windows itself and tells you which vulnerabilities your build still has and from which build they are fixed. Costs additional NVD requests; without an API key the first run takes much longer, afterwards the cache helps. Command line: -NoOsCheck (additionally -OsAllYears: also entries older than your Windows release)
• NVD API key (optional): free at nvd.nist.gov. Raises the limit from 5 to 50 requests per 30 seconds - the version check becomes much faster and more reliable. Command line: -NvdApiKey or the environment variable CVEWATCH_NVD_API_KEY
• NVD limit (default: on, 150 new requests per run): Only applies to individual requests - CVEs the bulk download does not cover (e.g. brand new in KEV, not yet marked by the NVD) or when the bulk download fails. Limits how many CVEs a run individually queries from the NVD; cached ones do not count. If the limit is not enough, the report clearly says "Scan incomplete" at the top and you need to scan again: the second run fetches the missing CVEs. Without a limit (untick the box) everything is checked in one run; without an API key that takes a long time. Command line: -NvdMaxCves NUMBER or -NoNvdLimit
• Use cache instead of downloading (default: off). See "Freshness & cache". Command line: -UseCache
• Outbound connections (all OFF by default, individually selectable): determine public IP (-PublicIP), measure internet latency (-Latency), download speed test (-SpeedTest); all three together: -External. Details under "Privacy & sources".
• Language: the "Deutsch" / "English" button at the top switches the window and the console output of the scan. The HTML report always contains both languages and has its own switch. Command line: -Lang en or -Lang de (default: en)'

    AddSec 'Freshness & cache' `
'The default is deliberate: KEV AND NVD data are downloaded fresh on EVERY run - a new, actively exploited CVE can be added at any time. "Use cache" is the fast or offline option: KEV and NVD data come from the local cache (NVD entries older than 30 days are still fetched again). The price: newly added vulnerabilities are missing (NVD data for CVEs that have been in KEV for more than 120 days may come from the cache even without this option, so that follow-up runs are fast; configurable at the top of the script), and NVD data stored without a severity (CVSS) only gets one after a run without cache. Without this option the cache only serves as a safety net in case CISA/NVD are briefly unreachable. NVD bulk sync: the first run downloads the NVD data of all KEV CVEs, every further run only the changes since the last run; every 30 days (or after a break of more than 119 days) everything is reloaded (state in nvd_kev_sync.json). The cache files (kev_catalog.json, nvd_cache_v2.json, nvd_kev_sync.json) are located under %USERPROFILE%\CVEwatch\assets and can be deleted at any time.'

    AddSec 'Command line & parameters' `
('For advanced users and automation. The window is only a front end: it starts the same script as a separate process with matching parameters. If you prefer the console or want to automate the scan (scheduled task, rollout), call the script directly - in the script folder, in PowerShell:

powershell -ExecutionPolicy Bypass -File .\{SKRIPT} [parameters]

Without parameters the scan runs directly in the console and opens the report at the end. All parameters are switches (just append them); only -NvdApiKey, -NvdMaxCves and -Lang take a value.

INTERFACE AND OUTPUT
• -Gui: starts this graphical interface instead of a console run.
• -NoOpen: does NOT open the report automatically at the end (the window uses this and opens it itself; useful for automation).
• -Lang en|de: language of window and console (default: en). The report always contains both languages.

SCOPE AND FRESHNESS
• -NoKev: skips KEV matching - inventory and posture only.
• -NoVersionCheck: skips only the NVD version check. KEV matching still runs, but there are no version ranges, no CVSS scores and no Windows build check.
• -NoOsCheck: skips only the Windows build check (KEV entries for Windows itself). Saves NVD requests.
• -OsAllYears: the build check also includes KEV entries older than your Windows release (default: skipped, saves requests; more NVD time).
• -UseCache: load KEV and NVD from the local cache instead of downloading (fast, also offline).
• -NvdApiKey KEY: uses an NVD API key (faster). The environment variable CVEWATCH_NVD_API_KEY is safer, because command line arguments are visible to others in the process list (the window therefore also passes the key via environment variable).

OUTBOUND CONNECTIONS (all off by default)
• -PublicIP: determine the public IP.
• -Latency: measure internet latency.
• -SpeedTest: download speed test.
• -External: shorthand for all three.

ADMINISTRATOR RIGHTS
• Without these switches, the console waits 10 seconds in an interactive session without administrator rights (key N = cancel) and then starts on its own - it never blocks.
• -AllowNonAdmin: continue silently without administrator rights (warning only in the log) - for rollouts.
• -RequireAdmin: without administrator rights, exit immediately with exit code 5, without scanning.

INTERNAL
• -StatusFile: progress file for the window - do not set manually.

EXAMPLES
• Window:  powershell -ExecutionPolicy Bypass -File .\{SKRIPT} -Gui
• Quick run without browser:  ... -File .\{SKRIPT} -UseCache -NoOpen
• Everything including network tests:  ... -File .\{SKRIPT} -External
• Scheduled task that reports only via exit code:  ... -File .\{SKRIPT} -RequireAdmin -NoOpen').Replace('{SKRIPT}', $sn)

    AddSec 'Reading the report' `
'Products and CVEs are sorted by real urgency: ransomware use -> CISA due date (overdue first) -> version verdict (affected > unclear > probably patched) -> match confidence -> CVSS score. Each product is a card you can expand; inside, each CVE has a row with:
• CVE: the identifier (click opens the NVD page with all details, e.g. references and patch links) and - if the NVD was queried - the CVSS severity (Critical, High, Medium, Low) with score. An orange dot after the identifier = known ransomware use.
• Match & version: confidence + basis show how reliable the match to the KEV product is (product + vendor vs. product name only). Below: "Installed" = your version. "Affected" = the vulnerable version ranges according to the NVD; the range containing YOUR version is marked red (e.g. "≥ 2.0 and < 2.4.1" means: from 2.0 up to before 2.4.1). "Fixed" = from which version the vulnerability is closed. The verdict summarizes: Affected, Probably patched or Unclear - for Unclear the reason is shown (e.g. no usable version in the inventory, no answer from the NVD).
• CISA due date: by when US federal agencies must close the vulnerability - a good yardstick for your own urgency.
• Vulnerability: name, description of the CVE (from CISA, English; long texts are shortened and can be expanded via "more") and the required action (italics).
• Windows itself: the report compares your Windows build (e.g. 10.0.26100.1234) with the KEV entries for Windows. For each release the NVD names the first build number in which the vulnerability is fixed. The verdict is Affected, Probably patched or Unclear (the NVD then gives no build limit); "Fixed" shows the build number. Entries that only affect other Windows releases are only counted (management summary).
• Hits with the verdict "Probably patched" are collapsed per product (toggle row in the table; visible when printing).
• Chrome and Edge: Chromium entries in KEV apply to both. For Edge the report uses the NVD version ranges if they name Edge; otherwise it infers from the major version (Edge 152 is based on Chromium 152). A higher major version than the fix counts as patched, a lower one as affected, the same one as unclear. The reason is shown in the report ("Derived: ...").
• Mouse-over explanations: technical terms (CVE, KEV, CVSS, confidence, verdict, due date, ransomware ...) and table headers show an explanation when you hover over them.
• Listening ports: the report shows which ports are reachable from outside and classifies them: green = normal Windows service (e.g. 135, 445, dynamic RPC ports, opened by the expected process), blue = known service, orange = remote access (RDP, SSH, VNC) or an unusual process on a standard port, red = outdated or unencrypted (Telnet, FTP). Green does not mean "safe", but "expected". The classification is explained via mouse-over on each row.
• Scan incomplete: if an orange notice appears at the top of the report, CVEs are still missing because the NVD limit was reached. Simply start the scan again (the cache saves time) or switch off the NVD limit.
• Scope of this scan (management summary): lists what the report does NOT check or checks only partially, e.g. Windows if the build check is off or the release is no longer supported, the version check of Microsoft 365 Apps (the NVD gives no build limits there; version and update status are shown), Chromium browsers other than Chrome and Edge (Brave, Vivaldi, Opera) or CVEs not checked against the NVD because of the limit. "No hits" always only means: no hits within the checked scope.
• Language: the "Deutsch / English" button at the top of the report switches the whole report.
Colors: red = affected/overdue, orange = due soon/ransomware, green = probably patched. Hits with the green verdict "Probably patched" count neither for the due date, nor the ransomware warning, nor the exit code. A green NEW marks hits added since the last run. Deliberately WITHOUT EPSS - for KEV, exploitation is already confirmed, a probability would be redundant.'

    AddSec 'Printing & sharing' `
'The report starts with a management summary (traffic light, findings by severity, the most important actions). At the top of the report there are buttons: print only the summary or the whole report - then choose "Save as PDF" in the browser print dialog. The inventory in the report can be searched (name, version, vendor; several terms possible, filter by source such as Registry or AppX) - this works directly in the browser, also offline. The report contains personal data (host name, user accounts, IP/MAC, installed software): share it only with authorized persons and delete it after use.'

    AddSec 'Security posture' `
'In addition to vulnerability matching: patch level, pending restart, operating system support, Secure Boot, BitLocker, TPM, RDP, SMBv1, UAC, registered antivirus products, local administrators, guest account, autologon, SMB shares, LSA protection, virtualization-based security/HVCI, Credential Guard, NTLM level, device join (Entra ID/domain) and open (listening) ports. Plus a separate Defender block (product, engine and signature version, real-time, tamper, cloud, PUA and network protection, ASR rules, exclusions, last scans). The storage section shows all drives (HDD/SSD/NVMe/USB) with health, usage and BitLocker status. Risky states are highlighted red, notices orange.'

    AddSec 'Exports & automation' `
'Each run creates several files under %USERPROFILE%\CVEwatch\assets\<computer name> (as SYSTEM, e.g. via Intune: %ProgramData%\CVEwatch\assets\<computer name>) - four of them can be opened with the buttons at the bottom of the window (always the newest, only clickable if present): report (HTML, readable), inventory (CSV), hits (JSON, machine-readable), log (host summary); plus a summary.json with the management findings by severity. The hits JSON also contains, per CVE, the description, the CVSS score, the affected version ranges, the fix hint and the reason for the verdict - handy for your own evaluations. The switches for automation are listed under "Command line & parameters"; the console never blocks waiting for input. The script outputs a CVEWATCH_SUMMARY line (incl. admin=0/1) and an exit code: 0 = clean, 2 = KEV hit with open version (not rated as patched), 3 = overdue due date, 4 = version affected (5 = administrator rights missing with -RequireAdmin). Ideal for a scheduled task that only reports when something is on fire.'

    AddSec 'Privacy & sources' `
'Everything runs locally; no inventory data is transmitted. By default only two requests go out: the KEV catalog (CISA, cisa.gov) and the NVD data of all KEV CVEs (NIST NVD, nvd.nist.gov) - this download is the same for every device and does not reveal which software is installed; only CVEs the NVD does not mark as KEV yet are requested individually by CVE identifier. CISA and NIST see your IP address. Public IP, latency measurement and speed test are opt-in (default: off): the IP lookup goes to api.ipify.org or ifconfig.me, the latency measurement pings www.google.de or www.devicentra.de, the speed test downloads 10 MB from crusadersoft.com (nothing is uploaded); the respective server sees your IP address. No telemetry, no sharing of your software list. Report and exports stay on this computer and contain personal data (e.g. host name, user accounts, IP/MAC): share only with authorized persons. Privacy policy: https://crusadersoft.com/#datenschutz
This product uses data from the NVD API but is not endorsed or certified by the NVD.'

    AddSec 'Enterprise' `
'This free version deliberately scans only the local device. Multi-report analysis (combining several reports), FleetScan (many hosts) and network scanning are reserved for the Enterprise edition - also for security reasons, so that not everyone can scan arbitrary networks. More at crusadersoft.com and cvewatch.de.'
    }

    # ---------------------------------------------------------------- Fenster
    $h = New-Object System.Windows.Forms.Form
    $h.Text = (G 'CVEwatch - Hilfe / Anleitung' 'CVEwatch - Help / Guide'); $h.Size = New-Object System.Drawing.Size(1020, 780)
    $h.MinimumSize = New-Object System.Drawing.Size(840, 560)
    $h.StartPosition = 'CenterScreen'; $h.BackColor = $cBg; $h.ForeColor = $cText
    $h.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $h.Icon = [System.Drawing.Icon]::FromHandle(([System.Drawing.Bitmap]::new((Reset-Stream $MAINiconstream)).GetHIcon()))
    $h.KeyPreview = $true

    # Kopfzeile: Titel + Logo
    $header = New-Object System.Windows.Forms.Panel; $header.Dock = 'Top'; $header.Height = 78; $header.BackColor = $cBg
    $lblT = New-Object System.Windows.Forms.Label
    $lblT.Text = (G 'Hilfe & Anleitung' 'Help & guide'); $lblT.Font = New-Object System.Drawing.Font('Segoe UI', 18, [System.Drawing.FontStyle]::Bold)
    $lblT.ForeColor = $cText; $lblT.AutoSize = $true; $lblT.Location = New-Object System.Drawing.Point(24, 10); $lblT.BackColor = [System.Drawing.Color]::Transparent
    $lblS = New-Object System.Windows.Forms.Label
    $lblS.Text = (G 'Scan, Report und Parameter erklärt - mit Inhaltsverzeichnis und Suche' 'Scan, report and parameters explained - with table of contents and search'); $lblS.ForeColor = $cMut; $lblS.AutoSize = $true
    $lblS.Location = New-Object System.Drawing.Point(27, 48); $lblS.BackColor = [System.Drawing.Color]::Transparent
    $header.Controls.Add($lblT); $header.Controls.Add($lblS)
    $logoBox = $null
    try {
        $ms2 = New-Object System.IO.MemoryStream(, $MAINlogostream.ToArray())
        $src = [System.Drawing.Image]::FromStream($ms2)
        $lw = 180; $lh = [int][Math]::Round($lw * $src.Height / $src.Width)
        $bm = New-Object System.Drawing.Bitmap($lw, $lh, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $g = [System.Drawing.Graphics]::FromImage($bm)
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic; $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.Clear([System.Drawing.Color]::Transparent)
        $g.DrawImage($src, (New-Object System.Drawing.Rectangle(0, 0, $lw, $lh)), 0, 0, $src.Width, $src.Height, [System.Drawing.GraphicsUnit]::Pixel)
        $g.Dispose()
        $logoBox = New-Object System.Windows.Forms.PictureBox
        $logoBox.Image = $bm; $logoBox.SizeMode = 'Normal'; $logoBox.BackColor = [System.Drawing.Color]::Transparent
        $logoBox.Size = New-Object System.Drawing.Size($lw, $lh); $logoBox.Top = [int][Math]::Max(4, (78 - $lh) / 2)
        $logoBox.Left = 800; $header.Controls.Add($logoBox)
    } catch { $logoBox = $null }   # ohne Logo funktioniert die Hilfe unverändert
    $header.Add_Resize({ if ($logoBox) { $logoBox.Left = $header.ClientSize.Width - $logoBox.Width - 24 } })
    $hdrLine = New-Object System.Windows.Forms.Panel; $hdrLine.Dock = 'Top'; $hdrLine.Height = 1; $hdrLine.BackColor = $cLine

    # Fußzeile: Links + Schließen
    $footer = New-Object System.Windows.Forms.Panel; $footer.Dock = 'Bottom'; $footer.Height = 54; $footer.BackColor = $cBg
    $ftLine = New-Object System.Windows.Forms.Panel; $ftLine.Dock = 'Bottom'; $ftLine.Height = 1; $ftLine.BackColor = $cLine
    $linkX = 24
    foreach ($lk in @(@('crusadersoft.com', 'https://crusadersoft.com'), @('cvewatch.de', 'https://cvewatch.de'), @((G 'Datenschutz' 'Privacy'), 'https://crusadersoft.com/#datenschutz'))) {
        $ll = New-Object System.Windows.Forms.LinkLabel
        $ll.Text = $lk[0]; $ll.Tag = $lk[1]; $ll.Location = New-Object System.Drawing.Point($linkX, 18); $ll.AutoSize = $true
        $ll.LinkColor = $cBlue; $ll.ActiveLinkColor = $cBlue; $ll.BackColor = $cBg
        $ll.Add_LinkClicked({ param($s, $e) try { Start-Process ([string]$s.Tag) } catch {} })
        $footer.Controls.Add($ll)
        $linkX += $ll.PreferredWidth + 28
    }
    $bc = New-Object System.Windows.Forms.Button
    $bc.Text = (G 'Schließen' 'Close'); $bc.Size = New-Object System.Drawing.Size(118, 32); $bc.Top = 11; $bc.Left = 860
    $bc.FlatStyle = 'Flat'; $bc.BackColor = $cSurf2; $bc.ForeColor = $cText
    $bc.Add_Click({ $h.Close() })
    $footer.Controls.Add($bc)
    $footer.Add_Resize({ $bc.Left = $footer.ClientSize.Width - $bc.Width - 24 })

    # Inhaltsverzeichnis (links)
    $navW = 244
    $nav = New-Object System.Windows.Forms.Panel; $nav.Dock = 'Left'; $nav.Width = $navW; $nav.BackColor = $cBg; $nav.AutoScroll = $true
    $sepV = New-Object System.Windows.Forms.Panel; $sepV.Dock = 'Left'; $sepV.Width = 1; $sepV.BackColor = $cLine
    $lblNav = New-Object System.Windows.Forms.Label
    $lblNav.Text = (G 'INHALT' 'CONTENTS'); $lblNav.Font = $fSub; $lblNav.ForeColor = $cMut; $lblNav.AutoSize = $false
    $lblNav.Location = New-Object System.Drawing.Point(0, 14); $lblNav.Size = New-Object System.Drawing.Size($navW, 26); $lblNav.Padding = New-Object System.Windows.Forms.Padding(21, 4, 0, 0)
    $nav.Controls.Add($lblNav)

    # Rechts: Suchleiste + Text
    $content = New-Object System.Windows.Forms.Panel; $content.Dock = 'Fill'; $content.BackColor = $cSurf
    $rtbWrap = New-Object System.Windows.Forms.Panel; $rtbWrap.Dock = 'Fill'; $rtbWrap.BackColor = $cSurf
    $rtbWrap.Padding = New-Object System.Windows.Forms.Padding(30, 6, 22, 12)
    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Dock = 'Fill'; $rtb.ReadOnly = $true; $rtb.BorderStyle = 'None'; $rtb.DetectUrls = $false; $rtb.HideSelection = $false
    $rtb.BackColor = $cSurf; $rtb.ForeColor = $cText; $rtb.Font = $fB; $rtb.ScrollBars = 'Vertical'; $rtb.TabStop = $false
    $rtbWrap.Controls.Add($rtb)
    $content.Controls.Add($rtbWrap)

    $sbar = New-Object System.Windows.Forms.Panel; $sbar.Dock = 'Top'; $sbar.Height = 56; $sbar.BackColor = $cSurf
    $sLine = New-Object System.Windows.Forms.Panel; $sLine.Dock = 'Bottom'; $sLine.Height = 1; $sLine.BackColor = $cLine; $sbar.Controls.Add($sLine)
    $lblSu = New-Object System.Windows.Forms.Label
    $lblSu.Text = (G 'Suche:' 'Search:'); $lblSu.ForeColor = $cMut; $lblSu.AutoSize = $true; $lblSu.Location = New-Object System.Drawing.Point(30, 19); $lblSu.BackColor = $cSurf
    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Font = New-Object System.Drawing.Font('Segoe UI', 10); $tb.Location = New-Object System.Drawing.Point(84, 14); $tb.Width = 290
    $tb.BackColor = $cBg; $tb.ForeColor = $cText; $tb.BorderStyle = 'FixedSingle'
    $bPrev = New-Object System.Windows.Forms.Button; $bNext = New-Object System.Windows.Forms.Button; $bClr = New-Object System.Windows.Forms.Button
    $bPrev.Text = [string][char]0x2191; $bNext.Text = [string][char]0x2193; $bClr.Text = [string][char]0x00D7
    $bx = 382
    foreach ($bb in @($bPrev, $bNext, $bClr)) {
        $bb.Size = New-Object System.Drawing.Size(30, 26); $bb.Location = New-Object System.Drawing.Point($bx, 13); $bx += 34
        $bb.FlatStyle = 'Flat'; $bb.BackColor = $cSurf2; $bb.ForeColor = $cText; $bb.TabStop = $false; $bb.Font = New-Object System.Drawing.Font('Segoe UI', 10)
        $sbar.Controls.Add($bb)
    }
    $lblCnt = New-Object System.Windows.Forms.Label
    $lblCnt.AutoSize = $true; $lblCnt.ForeColor = $cMut; $lblCnt.Location = New-Object System.Drawing.Point(($bx + 8), 19); $lblCnt.BackColor = $cSurf
    $sbar.Controls.Add($lblSu); $sbar.Controls.Add($tb); $sbar.Controls.Add($lblCnt)
    $content.Controls.Add($sbar)
    $tip = New-Object System.Windows.Forms.ToolTip
    $tip.SetToolTip($tb, (G 'Enter = nächster Treffer, Umschalt+Enter = vorheriger, Esc = leeren, Strg+F = Suche aus dem Text heraus öffnen' 'Enter = next match, Shift+Enter = previous, Esc = clear, Ctrl+F = open search from the text'))
    $tip.SetToolTip($bPrev, (G 'Vorheriger Treffer' 'Previous match')); $tip.SetToolTip($bNext, (G 'Nächster Treffer' 'Next match')); $tip.SetToolTip($bClr, (G 'Suche leeren' 'Clear search'))

    # Reihenfolge: zuletzt hinzugefügt wird zuerst angedockt
    $h.Controls.Add($content); $h.Controls.Add($sepV); $h.Controls.Add($nav)
    $h.Controls.Add($ftLine); $h.Controls.Add($footer); $h.Controls.Add($hdrLine); $h.Controls.Add($header)
    $null = $rtb.Handle   # Fenster-Handle anlegen, bevor formatiert wird

    # ---------------------------------------------------------------- Zustand + Zeichnen
    $st = @{ matches = (New-Object System.Collections.ArrayList); cur = -1; active = -1; lockUntil = [DateTime]::MinValue }
    $secStart   = New-Object System.Collections.ArrayList     # Textposition jeder Abschnittsüberschrift
    $codeRanges = New-Object System.Collections.ArrayList     # Befehlszeilen (eigener Hintergrund)
    $navItems   = New-Object System.Collections.ArrayList

    function Add-Par([string]$text, $font, $color, [int]$indent = 0, [int]$hang = 0, $back = $null) {
        $rtb.SelectionStart = $rtb.TextLength; $rtb.SelectionLength = 0
        $rtb.SelectionIndent = $indent; $rtb.SelectionHangingIndent = $hang
        $rtb.SelectionFont = $font; $rtb.SelectionColor = $color
        if ($back) { $rtb.SelectionBackColor = $back } else { $rtb.SelectionBackColor = $cSurf }
        $start = $rtb.TextLength
        $rtb.AppendText("$text`r`n")
        if ($back) { [void]$codeRanges.Add(@($start, $text.Length)) }
        return $start
    }
    # Aufzählungspunkt/Nummer + (optional fetter) Einleitungsteil bis zum ersten Doppelpunkt, Rest normal
    function Add-Item([string]$marker, $markerColor, [string]$body, [int]$indent, [int]$hang) {
        $rtb.SelectionStart = $rtb.TextLength; $rtb.SelectionLength = 0
        $rtb.SelectionIndent = $indent; $rtb.SelectionHangingIndent = $hang; $rtb.SelectionBackColor = $cSurf
        $rtb.SelectionFont = $fBold; $rtb.SelectionColor = $markerColor; $rtb.AppendText("$marker ")
        # fetter Einleitungsteil bis zum ersten ": " außerhalb von Klammern (z. B. nicht bei "(Standard: an)")
        $ci = -1; $depth = 0
        for ($k = 0; $k -lt [Math]::Min($body.Length - 1, 90); $k++) {
            $ch = $body[$k]
            if ($ch -eq '(') { $depth++ } elseif ($ch -eq ')') { if ($depth -gt 0) { $depth-- } }
            elseif ($ch -eq ':' -and $depth -eq 0 -and $body[$k + 1] -eq ' ') { $ci = $k; break }
        }
        if ($ci -gt 1 -and $ci -le 80 -and ($body.Substring(0, $ci) -notmatch '\.\s')) {
            $rtb.SelectionFont = $fBold; $rtb.SelectionColor = $cText; $rtb.AppendText($body.Substring(0, $ci + 1))
            $rtb.SelectionFont = $fB;    $rtb.SelectionColor = $cText; $rtb.AppendText($body.Substring($ci + 1) + "`r`n")
        } else {
            $rtb.SelectionFont = $fB; $rtb.SelectionColor = $cText; $rtb.AppendText($body + "`r`n")
        }
    }
    function Render-Section($sec, [int]$i) {
        if ($i -gt 0) { $null = Add-Par '' $fGap $cText; $null = Add-Par '' $fGap $cText }
        $pos = Add-Par $sec.T $fH $cBlue
        [void]$secStart.Add($pos)
        $null = Add-Par '' $fGap $cText
        foreach ($ln in ($sec.B -split "\r?\n")) {
            $t = $ln.TrimEnd()
            if ($t -eq '') { $null = Add-Par '' $fGap $cText; continue }
            if ($t -cmatch '^[A-ZÄÖÜ]{5,}[ A-ZÄÖÜ]*(?: \(.*\))?$') {                      # Zwischenüberschrift (GROSSBUCHSTABEN)
                $null = Add-Par '' $fGap $cText; $null = Add-Par $t $fSub $cTeal; continue
            }
            if ($t -match '^(powershell |\.\.\. )') {                                       # Befehlszeile
                $null = Add-Par $t $fMono $cCode 14 0 $cSurf2; continue
            }
            if ($t.StartsWith([string][char]0x2022 + ' ')) {                                # Aufzählung
                $body = $t.Substring(2)
                $cd = $body.IndexOf(':  ')
                if ($cd -gt 0 -and ($body.Substring($cd + 3).Trim() -match '^(powershell |\.\.\. )')) {   # Beispiel: Beschriftung + Befehl darunter
                    Add-Item ([string][char]0x2022) $cBlue ($body.Substring(0, $cd + 1)) 10 14
                    $null = Add-Par $body.Substring($cd + 3).Trim() $fMono $cCode 24 0 $cSurf2
                } else { Add-Item ([string][char]0x2022) $cBlue $body 10 14 }
                continue
            }
            if ($t -match '^(\d+\.)\s+(.*)$') { Add-Item $Matches[1] $cCode $Matches[2] 8 22; continue }   # nummerierte Schritte
            $null = Add-Par $t $fB $cText
        }
    }

    for ($i = 0; $i -lt $secs.Count; $i++) { Render-Section $secs[$i] $i }
    # Parameter, Dateinamen und Pfade im Fließtext als Code hervorheben
    $rxTok = [regex]'(?<![\w-])(?:-[A-Z][A-Za-z]{2,}|CVEWATCH_NVD_API_KEY|CVEWATCH_SUMMARY|%(?:USERPROFILE|ProgramData)%\\[\w\\<>%.\-]+|(?:kev_catalog|nvd_cache_v2|nvd_kev_sync|summary)\.json|\w+\.ps1)'
    foreach ($m in $rxTok.Matches($rtb.Text)) { $rtb.Select($m.Index, $m.Length); $rtb.SelectionFont = $fMono; $rtb.SelectionColor = $cCode }
    $rtb.Select(0, 0)

    # ---------------------------------------------------------------- Inhaltsverzeichnis: Einträge, Klick, Hervorhebung
    function Set-NavActive([int]$i) {
        for ($k = 0; $k -lt $navItems.Count; $k++) {
            $it = $navItems[$k]
            if ($k -eq $i) { $it.BackColor = $cSurf; $it.ForeColor = $cText; $it.Font = $fNavOn; $it.Controls[0].BackColor = $cBlue }
            else           { $it.BackColor = $cBg;   $it.ForeColor = $cMut;  $it.Font = $fNav;   $it.Controls[0].BackColor = $cBg }
        }
        $st.active = $i
    }
    function Go-Section([int]$i) {
        if ($i -lt 0 -or $i -ge $secStart.Count) { return }
        $st.lockUntil = [DateTime]::UtcNow.AddMilliseconds(700)     # Scroll-Ereignisse kurz ignorieren, damit der Klick nicht überschrieben wird
        $rtb.SelectionStart = $rtb.TextLength; $rtb.SelectionLength = 0; $rtb.ScrollToCaret()
        $rtb.Select([int]$secStart[$i], 0); $rtb.ScrollToCaret()
        Set-NavActive $i
    }
    for ($i = 0; $i -lt $secs.Count; $i++) {
        $it = New-Object System.Windows.Forms.Label
        $it.Text = ('{0:00}    {1}' -f ($i + 1), $secs[$i].T)
        $it.Location = New-Object System.Drawing.Point(0, (46 + $i * 34)); $it.Size = New-Object System.Drawing.Size($navW, 34)
        $it.Anchor = 'Top,Left,Right'; $it.TextAlign = 'MiddleLeft'; $it.Padding = New-Object System.Windows.Forms.Padding(21, 0, 4, 0)
        $it.Font = $fNav; $it.ForeColor = $cMut; $it.BackColor = $cBg; $it.Tag = $i; $it.Cursor = [System.Windows.Forms.Cursors]::Hand
        $bar = New-Object System.Windows.Forms.Panel; $bar.Dock = 'Left'; $bar.Width = 3; $bar.BackColor = $cBg; $bar.Cursor = [System.Windows.Forms.Cursors]::Hand
        $it.Controls.Add($bar)
        $it.Add_Click({ param($s, $e) Go-Section ([int]$s.Tag) })
        $bar.Add_Click({ param($s, $e) Go-Section ([int]$s.Parent.Tag) })
        $it.Add_MouseEnter({ param($s, $e) if ([int]$s.Tag -ne $st.active) { $s.BackColor = $cHover } })
        $it.Add_MouseLeave({ param($s, $e) if ([int]$s.Tag -ne $st.active) { $s.BackColor = $cBg } })
        $nav.Controls.Add($it); [void]$navItems.Add($it)
    }
    Set-NavActive 0
    function Update-Nav {
        if ([DateTime]::UtcNow -lt $st.lockUntil) { return }
        $k = 0
        $idx = $rtb.GetCharIndexFromPosition((New-Object System.Drawing.Point(14, 44)))
        for ($j = 0; $j -lt $secStart.Count; $j++) { if ([int]$secStart[$j] -le $idx) { $k = $j } }
        $bot = $rtb.GetCharIndexFromPosition((New-Object System.Drawing.Point(14, ($rtb.ClientSize.Height - 4))))
        if ($bot -ge ($rtb.TextLength - 3)) { $k = $secStart.Count - 1 }     # ganz unten: letzter Abschnitt
        if ($k -ne $st.active) { Set-NavActive $k }
    }
    $rtb.Add_VScroll({ Update-Nav })

    # ---------------------------------------------------------------- Suche
    function Show-Count {
        if ($tb.Text.Trim().Length -lt 2) { $lblCnt.ForeColor = $cMut; $lblCnt.Text = (G 'Enter = weiter, Umschalt+Enter = zurück' 'Enter = next, Shift+Enter = back'); return }
        if ($st.matches.Count -eq 0) { $lblCnt.ForeColor = $cAmb; $lblCnt.Text = (G 'Keine Treffer' 'No matches') }
        else { $lblCnt.ForeColor = $cText; $lblCnt.Text = ((G '{0} von {1}' '{0} of {1}') -f ($st.cur + 1), $st.matches.Count) }
    }
    function Clear-Hits {
        foreach ($r in $st.matches) { $rtb.Select([int]$r[0], [int]$r[1]); $rtb.SelectionBackColor = $cSurf }
        $st.matches.Clear(); $st.cur = -1
        foreach ($r in $codeRanges) { $rtb.Select([int]$r[0], [int]$r[1]); $rtb.SelectionBackColor = $cSurf2 }     # Befehlszeilen behalten ihren Hintergrund
    }
    function Go-Match([int]$i) {
        $n = $st.matches.Count
        if ($n -eq 0) { Show-Count; return }
        if ($st.cur -ge 0 -and $st.cur -lt $n) { $q = $st.matches[$st.cur]; $rtb.Select([int]$q[0], [int]$q[1]); $rtb.SelectionBackColor = $cHit }
        $i = (($i % $n) + $n) % $n
        $st.cur = $i
        $p = $st.matches[$i]
        $rtb.Select([int]$p[0], [int]$p[1]); $rtb.SelectionBackColor = $cCur
        $rtb.Select([int]$p[0], 0); $rtb.ScrollToCaret()
        Show-Count
    }
    function Step-Match([int]$d) { if ($st.matches.Count -gt 0) { Go-Match ($st.cur + $d) } }
    function Do-Search {
        Clear-Hits
        $q = $tb.Text.Trim()
        if ($q.Length -ge 2) {
            $ms = [regex]::Matches($rtb.Text, [regex]::Escape($q), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($m in $ms) {
                if ($st.matches.Count -ge 400) { break }
                $rtb.Select($m.Index, $m.Length); $rtb.SelectionBackColor = $cHit
                [void]$st.matches.Add(@($m.Index, $m.Length))
            }
            if ($st.matches.Count -gt 0) {
                $top = $rtb.GetCharIndexFromPosition((New-Object System.Drawing.Point(14, 8)))
                $first = 0
                for ($j = 0; $j -lt $st.matches.Count; $j++) { if ([int]$st.matches[$j][0] -ge $top) { $first = $j; break } }
                Go-Match $first
                return
            }
        }
        $rtb.Select(0, 0)
        Show-Count
    }
    $tb.Add_TextChanged({ Do-Search })
    $tb.Add_KeyDown({ param($s, $e) if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress = $true; Step-Match ($(if ($e.Shift) { -1 } else { 1 })) } })
    $bPrev.Add_Click({ Step-Match (-1) }); $bNext.Add_Click({ Step-Match 1 })
    $bClr.Add_Click({ $tb.Clear(); $tb.Focus() })
    $h.Add_KeyDown({ param($s, $e)
        if ($e.Control -and $e.KeyCode -eq 'F') { $tb.Focus(); $tb.SelectAll(); $e.SuppressKeyPress = $true; $e.Handled = $true }
        elseif ($e.KeyCode -eq 'F3') { Step-Match ($(if ($e.Shift) { -1 } else { 1 })); $e.Handled = $true }
        elseif ($e.KeyCode -eq 'Escape') { if ($tb.Text.Length -gt 0) { $tb.Clear() } else { $h.Close() }; $e.SuppressKeyPress = $true; $e.Handled = $true }
    })
    Show-Count
    $rtb.Select(0, 0); $rtb.ScrollToCaret()
    $h.ActiveControl = $tb
    [void]$h.ShowDialog()
}

# Läuft der aktuelle Prozess mit Administratorrechten?
function Test-IsAdmin {
    try { return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    catch { return $false }
}

function Show-CVEwatchGui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    $hostExe    = (Get-Process -Id $PID).Path
    if (-not $hostExe) { $hostExe = 'powershell.exe' }

    $cBg=[System.Drawing.Color]::FromArgb(13,17,23);    $cSurf=[System.Drawing.Color]::FromArgb(22,27,34)
    $cSurf2=[System.Drawing.Color]::FromArgb(28,34,48);  $cText=[System.Drawing.Color]::FromArgb(230,237,243)
    $cMut=[System.Drawing.Color]::FromArgb(139,148,158); $cRed=[System.Drawing.Color]::FromArgb(255,92,92)
    $cGrn=[System.Drawing.Color]::FromArgb(63,185,80);   $cBlue=[System.Drawing.Color]::FromArgb(88,166,255)
    $cAmber=[System.Drawing.Color]::FromArgb(240,160,32)
    $isAdminGui = Test-IsAdmin; $script:adminAck = $false

    # ---------------------------------------------------------------- Hilfsfunktionen fürs Aussehen
    $cLine  = [System.Drawing.Color]::FromArgb(48,54,61)
    $cBlueHover = [System.Drawing.Color]::FromArgb(121,184,255); $cBlueDown = [System.Drawing.Color]::FromArgb(66,140,230)
    $cSurf2Hover = [System.Drawing.Color]::FromArgb(40,48,66)
    $fCap  = New-Object System.Drawing.Font('Segoe UI',8.5,[System.Drawing.FontStyle]::Bold)
    $fStage   = New-Object System.Drawing.Font('Segoe UI',10)
    $fStageOn = New-Object System.Drawing.Font('Segoe UI',10,[System.Drawing.FontStyle]::Bold)
    $gIdle = [string][char]0x25CB; $gRun = [string][char]0x25CF; $gDone = [string][char]0x2713      # ○ ● ✓

    function New-RoundPath([int]$w,[int]$h,[int]$r) {
        $d = $r*2; $gp = New-Object System.Drawing.Drawing2D.GraphicsPath
        $gp.AddArc(0,0,$d,$d,180,90); $gp.AddArc($w-$d-1,0,$d,$d,270,90)
        $gp.AddArc($w-$d-1,$h-$d-1,$d,$d,0,90); $gp.AddArc(0,$h-$d-1,$d,$d,90,90); $gp.CloseFigure()
        return $gp
    }
    function Set-Round($ctl,[int]$r) { $gp = New-RoundPath $ctl.Width $ctl.Height $r; $ctl.Region = New-Object System.Drawing.Region($gp); $gp.Dispose() }
    # Karte: dunkle Fläche mit runden Ecken, feinem Rand und Kleinschrift-Überschrift
    function New-Card([string]$caption,[int]$x,[int]$y,[int]$w,[int]$h) {
        $p = New-Object System.Windows.Forms.Panel
        $p.Location = New-Object System.Drawing.Point($x,$y); $p.Size = New-Object System.Drawing.Size($w,$h); $p.BackColor = $cSurf
        $lb = New-Object System.Windows.Forms.Label
        $lb.Text = $caption.ToUpper(); $lb.Font = $fCap; $lb.ForeColor = $cMut; $lb.AutoSize = $true; $lb.BackColor = $cSurf
        $lb.Location = New-Object System.Drawing.Point(16,13)
        $p.Controls.Add($lb)
        Set-Round $p 10
        $p.Add_Paint({ param($s,$e)
            $g = $e.Graphics; $g.SmoothingMode = 'AntiAlias'
            $path = New-RoundPath $s.Width $s.Height 10; $pen = New-Object System.Drawing.Pen($cLine,2)
            $g.DrawPath($pen,$path); $pen.Dispose(); $path.Dispose()
        })
        return $p
    }
    function Style-Button($b,[bool]$primary,[int]$radius = 8) {
        $b.FlatStyle = 'Flat'; $b.FlatAppearance.BorderSize = 0; $b.Cursor = [System.Windows.Forms.Cursors]::Hand
        if ($primary) { $b.BackColor = $cBlue; $b.ForeColor = [System.Drawing.Color]::Black; $b.FlatAppearance.MouseOverBackColor = $cBlueHover; $b.FlatAppearance.MouseDownBackColor = $cBlueDown }
        else          { $b.BackColor = $cSurf2; $b.ForeColor = $cText; $b.FlatAppearance.MouseOverBackColor = $cSurf2Hover; $b.FlatAppearance.MouseDownBackColor = $cSurf }
        Set-Round $b $radius
    }

    # ---------------------------------------------------------------- Fenster
    $form = New-Object System.Windows.Forms.Form
    $form.Text=$(if ($isAdminGui) { "CVEwatch - Asset Scanner v$ScriptVersion" } else { (G "CVEwatch - Asset Scanner v$ScriptVersion (kein Administrator - eingeschränkt)" "CVEwatch - Asset Scanner v$ScriptVersion (not administrator - limited)") })
    $form.ClientSize=New-Object System.Drawing.Size(780,854)
    $form.StartPosition='CenterScreen'; $form.BackColor=$cBg; $form.ForeColor=$cText
    $form.Font=New-Object System.Drawing.Font('Segoe UI',9)
    $form.Icon=[System.Drawing.Icon]::FromHandle(([System.Drawing.Bitmap]::new((Reset-Stream $MAINiconstream)).GetHIcon()))
    $form.MaximizeBox=$false; $form.MinimizeBox=$false
    $form.FormBorderStyle="FixedDialog"

    # Kopfzeile: Titel, Untertitel, Administrator-Hinweis, Hilfe-Knopf (Logo siehe unten)
    $title=New-Object System.Windows.Forms.Label
    $title.Text='CVEwatch Asset Scan'; $title.Font=New-Object System.Drawing.Font('Segoe UI',20,[System.Drawing.FontStyle]::Bold)
    $title.ForeColor=$cText; $title.Location='22,10'; $title.AutoSize=$true; $form.Controls.Add($title)
    $lblVer=New-Object System.Windows.Forms.Label
    $lblVer.Text="v$ScriptVersion"; $lblVer.ForeColor=$cMut; $lblVer.AutoSize=$true
    $lblVer.Font=New-Object System.Drawing.Font('Segoe UI',10)
    $lblVer.Location=New-Object System.Drawing.Point((22 + $title.PreferredWidth + 2), 24)
    $form.Controls.Add($lblVer)

    $lblSubT=New-Object System.Windows.Forms.Label
    $lblSubT.Text=(G 'Inventar, KEV- und NVD-Abgleich für Windows' 'Inventory, KEV and NVD check for Windows'); $lblSubT.ForeColor=$cMut; $lblSubT.AutoSize=$true; $lblSubT.Location='26,50'
    $form.Controls.Add($lblSubT)
    $lblAdm=New-Object System.Windows.Forms.Label
    $lblAdm.Text=$(if ($isAdminGui) { ([string][char]0x25CF + '  Administrator') } else { ([string][char]0x25CF + (G '  kein Administrator - eingeschränkt' '  not administrator - limited')) })
    $lblAdm.ForeColor=$(if ($isAdminGui) { $cGrn } else { $cAmber }); $lblAdm.AutoSize=$true
    $lblAdm.Location=New-Object System.Drawing.Point((26 + $lblSubT.PreferredWidth + 20), 50)
    $form.Controls.Add($lblAdm)

    $btnHelp=New-Object System.Windows.Forms.Button
    $btnHelp.Text=(G '?   Hilfe / Anleitung' '?   Help / Guide'); $btnHelp.Location='606,22'; $btnHelp.Size='150,32'
    Style-Button $btnHelp $false
    $form.Controls.Add($btnHelp)

    # Sprachknopf: zeigt die ANDERE Sprache an; baut das Fenster in der neuen Sprache neu auf (nicht während eines Scans)
    $btnLang=New-Object System.Windows.Forms.Button
    $btnLang.Text=(G 'English' 'Deutsch'); $btnLang.Location='506,22'; $btnLang.Size='90,32'
    Style-Button $btnLang $false
    $form.Controls.Add($btnLang)
    $btnLang.Add_Click({
        if ($script:proc) { return }
        $script:Lang = if ($script:Lang -eq 'de') { 'en' } else { 'de' }
        $script:GuiRestart = $true
        $form.Close()
    })

    # --- Logo (Base64 aus dem Skriptkopf): Schriftzug klein links neben dem Hilfe-Knopf, beim Überfahren groß ---
    # Das eingebettete Logo ist bereits auf den Schriftzug zugeschnitten (transparent, ohne Metadaten);
    # hier wird es nur skaliert. Die große Ansicht liegt auf einer hellen Karte, weil das blaue Logo auf Weiß am besten lesbar ist.
    try {
        $logoImg = [System.Drawing.Image]::FromStream((Reset-Stream $MAINlogostream))
        $scaleLogo = {
            param($img, [int]$w, [int]$h)
            $ia = New-Object System.Drawing.Imaging.ImageAttributes; $ia.SetWrapMode([System.Drawing.Drawing2D.WrapMode]::TileFlipXY)   # kein heller Rand am Bildrand
            $big = New-Object System.Drawing.Bitmap(($w*4), ($h*4), [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)   # erst grob, dann fein: weniger Treppeneffekt
            $g = [System.Drawing.Graphics]::FromImage($big)
            $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic; $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $g.Clear([System.Drawing.Color]::Transparent)
            $g.DrawImage($img, (New-Object System.Drawing.Rectangle(0, 0, ($w*4), ($h*4))), 0, 0, $img.Width, $img.Height, [System.Drawing.GraphicsUnit]::Pixel, $ia); $g.Dispose()
            $bmp = New-Object System.Drawing.Bitmap($w, $h, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
            $g2 = [System.Drawing.Graphics]::FromImage($bmp)
            $g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic; $g2.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $g2.Clear([System.Drawing.Color]::Transparent)
            $g2.DrawImage($big, (New-Object System.Drawing.Rectangle(0, 0, $w, $h)), 0, 0, $big.Width, $big.Height, [System.Drawing.GraphicsUnit]::Pixel, $ia); $g2.Dispose(); $big.Dispose(); $ia.Dispose()
            $bmp
        }
        $logoRatio = $logoImg.Height / $logoImg.Width

        # Klein: ganzer Schriftzug, rechtsbündig direkt links neben dem Hilfe-Knopf, vertikal auf Knopfmitte
        $freeW  = $btnLang.Left - 10 - ($lblVer.Left + $lblVer.PreferredWidth + 12)   # Platz zwischen Titel/Version und Knopf
        $smallW = [int][Math]::Max(70, [Math]::Min(140, $freeW))
        $smallH = [int][Math]::Max(1, [Math]::Round($smallW * $logoRatio))
        $picLogo = New-Object System.Windows.Forms.PictureBox
        $picLogo.Image = (& $scaleLogo $logoImg $smallW $smallH)
        $picLogo.Size = New-Object System.Drawing.Size($smallW, $smallH); $picLogo.SizeMode = 'Normal'; $picLogo.BackColor = [System.Drawing.Color]::Transparent
        $picLogo.Location = New-Object System.Drawing.Point(($btnLang.Left - 10 - $smallW), ($btnHelp.Top + [int][Math]::Round(($btnHelp.Height - $smallH) / 2)))
        $picLogo.Cursor = [System.Windows.Forms.Cursors]::Hand
        $form.Controls.Add($picLogo)

        # Groß (beim Überfahren): ganzer Schriftzug auf heller Karte, rechtsbündig unter dem Hilfe-Knopf, bleibt im Fenster
        $bigW = 380; $bigH = [int][Math]::Round($bigW * $logoRatio)
        $picBig = New-Object System.Windows.Forms.PictureBox
        $picBig.Image = (& $scaleLogo $logoImg $bigW $bigH)
        $picBig.Size = New-Object System.Drawing.Size(($bigW + 40), ($bigH + 40)); $picBig.SizeMode = 'CenterImage'
        $picBig.BackColor = [System.Drawing.Color]::White; $picBig.BorderStyle = 'FixedSingle'; $picBig.Visible = $false
        $picBig.Location = New-Object System.Drawing.Point(([Math]::Max(8, ($btnHelp.Right - $picBig.Width))), ($btnHelp.Bottom + 6))
        $form.Controls.Add($picBig)
        $picLogo.Add_MouseEnter({ $picBig.BringToFront(); $picBig.Visible = $true })
        $picLogo.Add_MouseLeave({ $picBig.Visible = $false })
        $picBig.Add_MouseLeave({ $picBig.Visible = $false })
    } catch { }   # ohne Logo funktioniert die GUI unverändert

    $hdrLine=New-Object System.Windows.Forms.Panel; $hdrLine.Location='0,80'; $hdrLine.Size='780,1'; $hdrLine.BackColor=$cLine; $form.Controls.Add($hdrLine)

    $sub=New-Object System.Windows.Forms.Label
    $sub.Text=(G 'Agentless KEV-Triage für Windows: findet installierte Produkte, die in aktiv ausgenutzten Schwachstellen (CISA KEV) vorkommen, und prüft per NVD, ob deine Version betroffen ist. Alles läuft lokal - nach außen gehen nur KEV-/NVD-Abrufe; IP-Abfrage, Latenz und Speedtest nur, wenn du sie unten aktivierst.' 'Agentless KEV triage for Windows: finds installed products that appear in actively exploited vulnerabilities (CISA KEV) and checks via the NVD whether your version is affected. Everything runs locally - only KEV/NVD requests go out; IP lookup, latency and speed test only if you enable them below.')
    $sub.ForeColor=$cMut; $sub.Location='26,90'; $sub.Size='730,46'; $form.Controls.Add($sub)

    # Karte "Ablauf"
    $gb = New-Card (G 'Ablauf' 'Process') 24 140 350 292
    $form.Controls.Add($gb)
    $stages=[ordered]@{ 'system'='System + Hardware'; 'posture'=(G 'Sicherheits-Posture' 'Security posture'); 'net'=(G 'Netzwerk' 'Network');
        'inv'=(G 'Software-Inventar' 'Software inventory'); 'kev'=(G 'KEV-Katalog laden' 'Load KEV catalog'); 'match'=(G 'KEV-Abgleich' 'KEV matching');
        'nvd'=(G 'Versionsabgleich (NVD)' 'Version check (NVD)'); 'report'=(G 'HTML-Report erzeugen' 'Create HTML report') }
    $stageOrder=@('system','posture','net','inv','kev','match','nvd','report')
    $stageLabels=@{}; $yy=40
    foreach ($k in $stages.Keys) {
        $l=New-Object System.Windows.Forms.Label
        $l.Text="$gIdle   $($stages[$k])"; $l.Font=$fStage; $l.ForeColor=$cMut; $l.Location="16,$yy"; $l.Size='318,24'
        $gb.Controls.Add($l); $stageLabels[$k]=$l; $yy+=25
    }

    # Karte "Optionen"
    $gbo = New-Card (G 'Optionen' 'Options') 390 140 366 292
    $form.Controls.Add($gbo)

    $cbKev=New-Object System.Windows.Forms.CheckBox
    $cbKev.Text=(G 'KEV-Abgleich: aktiv ausgenutzte Lücken finden' 'KEV matching: find actively exploited vulnerabilities'); $cbKev.Checked=$true; $cbKev.ForeColor=$cText
    $cbKev.Location='16,40'; $cbKev.Size='338,22'; $gbo.Controls.Add($cbKev)

    $cbVer=New-Object System.Windows.Forms.CheckBox
    $cbVer.Text=(G '+ NVD-Versionsabgleich (Version betroffen?)' '+ NVD version check (is my version affected?)'); $cbVer.Checked=$true; $cbVer.ForeColor=$cText
    $cbVer.Location='36,64'; $cbVer.Size='318,22'; $gbo.Controls.Add($cbVer)

    $cbOs=New-Object System.Windows.Forms.CheckBox
    $cbOs.Text=(G '+ Windows-Build prüfen (KEV-Einträge zu Windows)' '+ Check Windows build (KEV entries for Windows)'); $cbOs.Checked=$true; $cbOs.ForeColor=$cText
    $cbOs.Location='36,88'; $cbOs.Size='318,22'; $gbo.Controls.Add($cbOs)
    # Abhängigkeiten: Build-Abgleich braucht den NVD-Versionsabgleich, dieser den KEV-Abgleich (ohne KEV-Abgleich wird auch der Versionsabgleich abgewählt; der Build-Abgleich behält sein Häkchen und wird nur gedämpft)
    $cbKev.Add_CheckedChanged({ $cbVer.Enabled=$cbKev.Checked; if (-not $cbKev.Checked) { $cbVer.Checked=$false }; $cbOs.Enabled=($cbKev.Checked -and $cbVer.Checked) })
    $cbVer.Add_CheckedChanged({ $cbOs.Enabled=($cbKev.Checked -and $cbVer.Checked) })

    $lblKey=New-Object System.Windows.Forms.Label
    $lblKey.Text=(G 'NVD API-Key (optional, schneller):' 'NVD API key (optional, faster):'); $lblKey.ForeColor=$cMut; $lblKey.Location='16,116'; $lblKey.Size='338,18'
    $gbo.Controls.Add($lblKey)
    $tbKey=New-Object System.Windows.Forms.TextBox
    $tbKey.Location='16,136'; $tbKey.Size='334,24'; $tbKey.BackColor=$cBg; $tbKey.ForeColor=$cText; $tbKey.BorderStyle='FixedSingle'
    $tbKey.UseSystemPasswordChar=$true   # Key nicht im Klartext anzeigen (Bildschirmfreigabe, Screenshots)
    $gbo.Controls.Add($tbKey)

    $cbCache=New-Object System.Windows.Forms.CheckBox
    $cbCache.Text=(G 'Cache verwenden statt frisch laden (schneller)' 'Use cache instead of downloading (faster)'); $cbCache.Checked=$false; $cbCache.ForeColor=$cMut
    $cbCache.Location='16,168'; $cbCache.Size='338,22'; $gbo.Controls.Add($cbCache)

    $cbLimit=New-Object System.Windows.Forms.CheckBox
    $cbLimit.Text=(G 'NVD-Limit: höchstens 150 neue Abfragen pro Lauf' 'NVD limit: at most 150 new requests per run'); $cbLimit.Checked=$true; $cbLimit.ForeColor=$cText
    $cbLimit.Location='16,190'; $cbLimit.Size='338,22'; $gbo.Controls.Add($cbLimit)

    $lblHint=New-Object System.Windows.Forms.Label
    $lblHint.Text=(G 'Ohne KEV-Abgleich: nur Inventar, Posture & Netzwerk. Neue KEV-CVEs werden immer frisch geladen.' 'Without KEV matching: inventory, posture & network only. New KEV CVEs are always downloaded fresh.')
    $lblHint.Font=New-Object System.Drawing.Font('Segoe UI',8.5); $lblHint.ForeColor=$cMut; $lblHint.Location='16,214'; $lblHint.Size='338,30'; $gbo.Controls.Add($lblHint)

    $btnStart=New-Object System.Windows.Forms.Button
    $btnStart.Text=(G 'Scan starten' 'Start scan'); $btnStart.Location='16,246'; $btnStart.Size='334,38'
    $btnStart.Font=New-Object System.Drawing.Font('Segoe UI',10.5,[System.Drawing.FontStyle]::Bold)
    Style-Button $btnStart $true 10
    $gbo.Controls.Add($btnStart)

    # --- Verbindungen nach außen: alles Opt-in, Standard AUS (Datenschutz durch Voreinstellung) ---
    $gbx = New-Card (G 'Verbindungen nach außen' 'Outbound connections') 24 444 732 118
    $form.Controls.Add($gbx)
    $lblOpt=New-Object System.Windows.Forms.Label
    $lblOpt.Text=(G 'optional, standardmäßig aus' 'optional, off by default'); $lblOpt.ForeColor=$cMut; $lblOpt.AutoSize=$true; $lblOpt.BackColor=$cSurf
    $lblOpt.Location=New-Object System.Drawing.Point((16 + $gbx.Controls[0].PreferredWidth + 10), 12); $gbx.Controls.Add($lblOpt)

    $cbIP=New-Object System.Windows.Forms.CheckBox
    $cbIP.Text=(G 'Öffentliche IP ermitteln' 'Determine public IP'); $cbIP.Checked=$false; $cbIP.ForeColor=$cText; $cbIP.Location='16,38'; $cbIP.Size='210,22'; $gbx.Controls.Add($cbIP)
    $lblIP=New-Object System.Windows.Forms.Label
    $lblIP.Text=(G 'Anfrage an api.ipify.org / ifconfig.me (Drittanbieter sehen deine IP)' 'Request to api.ipify.org / ifconfig.me (third parties see your IP)'); $lblIP.ForeColor=$cMut; $lblIP.Location='232,41'; $lblIP.Size='486,18'; $gbx.Controls.Add($lblIP)
    $cbLat=New-Object System.Windows.Forms.CheckBox
    $cbLat.Text=(G 'Internet-Latenz messen' 'Measure internet latency'); $cbLat.Checked=$false; $cbLat.ForeColor=$cText; $cbLat.Location='16,62'; $cbLat.Size='210,22'; $gbx.Controls.Add($cbLat)
    $lblLat=New-Object System.Windows.Forms.Label
    $lblLat.Text=(G 'Ping an www.google.de / www.devicentra.de (die Ziele sehen deine IP)' 'Ping to www.google.de / www.devicentra.de (the targets see your IP)'); $lblLat.ForeColor=$cMut; $lblLat.Location='232,65'; $lblLat.Size='486,18'; $gbx.Controls.Add($lblLat)
    $cbSpeed=New-Object System.Windows.Forms.CheckBox
    $cbSpeed.Text=(G 'Download-Speedtest' 'Download speed test'); $cbSpeed.Checked=$false; $cbSpeed.ForeColor=$cText; $cbSpeed.Location='16,86'; $cbSpeed.Size='210,22'; $gbx.Controls.Add($cbSpeed)
    $lblSpd=New-Object System.Windows.Forms.Label
    $lblSpd.Text=(G 'lädt 10 MB von crusadersoft.com (dessen Server-Log enthält deine IP)' 'downloads 10 MB from crusadersoft.com (its server log contains your IP)'); $lblSpd.ForeColor=$cMut; $lblSpd.Location='232,89'; $lblSpd.Size='486,18'; $gbx.Controls.Add($lblSpd)
    $llDs=New-Object System.Windows.Forms.LinkLabel
    $llDs.Text=(G 'Was wird übertragen? Datenschutzerklärung' 'What is transmitted? Privacy policy'); $llDs.AutoSize=$true
    $llDs.LinkColor=$cBlue; $llDs.ActiveLinkColor=$cBlue; $llDs.BackColor=$cSurf
    $llDs.Location=New-Object System.Drawing.Point((732 - 16 - $llDs.PreferredWidth), 12)
    $llDs.Add_LinkClicked({ try { Start-Process 'https://crusadersoft.com/#datenschutz' } catch {} })
    $gbx.Controls.Add($llDs)

    # Fortschritt: schlanker Balken (Spur + Füllung) mit Prozentanzeige; Werte setzt Set-Progress
    $pb=New-Object System.Windows.Forms.Panel; $pb.Location='24,578'; $pb.Size='676,8'; $pb.BackColor=$cSurf2; $form.Controls.Add($pb)
    Set-Round $pb 4
    $pbFill=New-Object System.Windows.Forms.Panel; $pbFill.Location='0,0'; $pbFill.Size=New-Object System.Drawing.Size(0,8); $pbFill.BackColor=$cBlue; $pb.Controls.Add($pbFill)
    $pctLbl=New-Object System.Windows.Forms.Label
    $pctLbl.Text='0 %'; $pctLbl.ForeColor=$cMut; $pctLbl.TextAlign='MiddleRight'; $pctLbl.Location='706,572'; $pctLbl.Size='50,20'; $form.Controls.Add($pctLbl)

    # Karte "Protokoll"
    $gbl = New-Card (G 'Protokoll' 'Log') 24 598 732 138
    $form.Controls.Add($gbl)
    $logbox=New-Object System.Windows.Forms.RichTextBox
    $logbox.Location='14,34'; $logbox.Size='704,96'; $logbox.BackColor=$cSurf; $logbox.ForeColor=$cText
    $logbox.ReadOnly=$true; $logbox.Font=New-Object System.Drawing.Font('Consolas',9); $logbox.BorderStyle='None'
    $gbl.Controls.Add($logbox)

    $status=New-Object System.Windows.Forms.Label
    $status.Text=$(if ($isAdminGui) { (G 'Bereit.' 'Ready.') } else { (G 'Bereit. Hinweis: nicht als Administrator gestartet, der Scan wird unvollständig.' 'Ready. Note: not started as administrator, the scan will be incomplete.') }); $status.ForeColor=$(if ($isAdminGui) { $cMut } else { $cAmber }); $status.Font=New-Object System.Drawing.Font('Segoe UI',9.5)
    $status.Location='26,746'; $status.Size='730,22'; $form.Controls.Add($status)

    # Export-Knöpfe: je nur klickbar, wenn ein Bericht dieser Art vorliegt (es wird immer der neueste geöffnet)
    $btnHtml=New-Object System.Windows.Forms.Button
    $btnHtml.Text='Report (HTML)'; $btnHtml.Location='24,772'; $btnHtml.Size='174,36'; $btnHtml.Enabled=$false
    Style-Button $btnHtml $true; $form.Controls.Add($btnHtml)
    $btnCsv=New-Object System.Windows.Forms.Button
    $btnCsv.Text=(G 'Inventar (CSV)' 'Inventory (CSV)'); $btnCsv.Location='210,772'; $btnCsv.Size='174,36'; $btnCsv.Enabled=$false
    Style-Button $btnCsv $false; $form.Controls.Add($btnCsv)
    $btnJson=New-Object System.Windows.Forms.Button
    $btnJson.Text=(G 'Treffer (JSON)' 'Hits (JSON)'); $btnJson.Location='396,772'; $btnJson.Size='174,36'; $btnJson.Enabled=$false
    Style-Button $btnJson $false; $form.Controls.Add($btnJson)
    $btnLog=New-Object System.Windows.Forms.Button
    $btnLog.Text='Log (TXT)'; $btnLog.Location='582,772'; $btnLog.Size='174,36'; $btnLog.Enabled=$false
    Style-Button $btnLog $false; $form.Controls.Add($btnLog)
    # Aussehen folgt dem Zustand: deaktiviert = gedämpft, aktiv = Primär- bzw. Sekundärfarbe
    $primaryBtns = @($btnStart, $btnHtml)
    $enabledLook = {
        param($s,$e)
        if (-not $s.Enabled) { $s.BackColor = $cSurf2; $s.ForeColor = $cMut }
        elseif ($primaryBtns -contains $s) { $s.BackColor = $cBlue; $s.ForeColor = [System.Drawing.Color]::Black }
        else { $s.BackColor = $cSurf2; $s.ForeColor = $cText }
    }
    foreach ($bb in @($btnStart, $btnHtml, $btnCsv, $btnJson, $btnLog)) { $bb.Add_EnabledChanged($enabledLook) }
    foreach ($bb in @($btnHtml, $btnCsv, $btnJson, $btnLog)) { if (-not $bb.Enabled) { $bb.BackColor = $cSurf2; $bb.ForeColor = $cMut } }

    # Footer: Links + Enterprise-Hinweis
    $llCrusader=New-Object System.Windows.Forms.LinkLabel
    $llCrusader.Text='crusadersoft.com'; $llCrusader.Location='24,822'; $llCrusader.AutoSize=$true
    $llCrusader.LinkColor=$cBlue; $llCrusader.ActiveLinkColor=$cBlue; $llCrusader.BackColor=$cBg
    $llCrusader.Add_LinkClicked({ try { Start-Process 'https://crusadersoft.com' } catch {} })
    $form.Controls.Add($llCrusader)
    $llCve=New-Object System.Windows.Forms.LinkLabel
    $llCve.Text='cvewatch.de'; $llCve.Location='148,822'; $llCve.AutoSize=$true
    $llCve.LinkColor=$cBlue; $llCve.ActiveLinkColor=$cBlue; $llCve.BackColor=$cBg
    $llCve.Add_LinkClicked({ try { Start-Process 'https://cvewatch.de' } catch {} })
    $form.Controls.Add($llCve)
    $llDsF=New-Object System.Windows.Forms.LinkLabel
    $llDsF.Text=(G 'Datenschutz' 'Privacy'); $llDsF.Location='238,822'; $llDsF.AutoSize=$true
    $llDsF.LinkColor=$cBlue; $llDsF.ActiveLinkColor=$cBlue; $llDsF.BackColor=$cBg
    $llDsF.Add_LinkClicked({ try { Start-Process 'https://crusadersoft.com/#datenschutz' } catch {} })
    $form.Controls.Add($llDsF)
    $llEnt=New-Object System.Windows.Forms.Label
    $llEnt.Text=(G 'Multi-Report-Auswertung · FleetScan · Netzwerkscan: nur Enterprise.' 'Multi-report analysis · FleetScan · network scan: Enterprise only.')
    $llEnt.ForeColor=$cMut; $llEnt.TextAlign='MiddleRight'; $llEnt.Location='336,822'; $llEnt.Size='420,18'; $form.Controls.Add($llEnt)

    # Tooltips: kurze Erklärung zu jeder Option
    $tt=New-Object System.Windows.Forms.ToolTip; $tt.AutoPopDelay=25000; $tt.InitialDelay=400; $tt.ReshowDelay=200
    $tt.SetToolTip($cbKev,(G 'Gleicht die installierte Software mit dem CISA-KEV-Katalog ab (Schwachstellen, die nachweislich aktiv ausgenutzt werden). Dafür wird der Katalog von cisa.gov geladen.' 'Matches the installed software against the CISA KEV catalog (vulnerabilities that are known to be actively exploited). The catalog is downloaded from cisa.gov for this.'))
    $tt.SetToolTip($cbLimit,(G 'Mit Limit werden pro Lauf höchstens 150 NEUE CVEs bei der NVD abgefragt (bereits gespeicherte zählen nicht). Fehlende CVEs holt der nächste Scan nach; der Report sagt dann deutlich "Scan unvollständig". Ohne Limit (Haken entfernen) werden alle in einem Lauf geprüft, ohne API-Key kann das viele Minuten dauern.' 'With the limit, at most 150 NEW CVEs are queried from the NVD per run (cached ones do not count). The next scan fetches the missing CVEs; the report then clearly says "Scan incomplete". Without the limit (untick) all are checked in one run; without an API key this can take many minutes.'))
    $tt.SetToolTip($cbOs,(G 'Vergleicht deinen exakten Windows-Build mit den KEV-Einträgen zu Windows selbst (die NVD nennt je Release die Build-Nummer, ab der eine Lücke behoben ist). Die Daten kommen aus dem NVD-Sammelabruf; es werden keine Inventardaten übertragen.' 'Compares your exact Windows build with the KEV entries for Windows itself (for each release the NVD names the build number in which a vulnerability is fixed). The data comes from the NVD bulk download; no inventory data is transmitted.'))
    $tt.SetToolTip($cbVer,(G 'Prüft anhand der NVD (nvd.nist.gov), ob die installierte Version im verwundbaren Bereich liegt. Die NVD-Daten aller KEV-CVEs werden gesammelt geladen; es werden keine Inventardaten übertragen.' 'Checks against the NVD (nvd.nist.gov) whether the installed version is in the vulnerable range. The NVD data of all KEV CVEs is downloaded in bulk; no inventory data is transmitted.'))
    $tt.SetToolTip($tbKey,(G 'Optionaler, kostenloser Schlüssel von nvd.nist.gov: erhöht das Limit von 5 auf 50 Anfragen pro 30 Sekunden.' 'Optional, free key from nvd.nist.gov: raises the limit from 5 to 50 requests per 30 seconds.'))
    $tt.SetToolTip($cbCache,(G 'Nutzt zwischengespeicherte KEV-/NVD-Daten statt sie neu zu laden: schneller und ohne Internetzugriff, aber eventuell nicht mehr aktuell.' 'Uses cached KEV/NVD data instead of downloading it again: faster and without internet access, but possibly out of date.'))
    $tt.SetToolTip($cbIP,(G 'Ermittelt die öffentliche IP-Adresse über api.ipify.org bzw. ifconfig.me (Drittanbieter). Standardmäßig aus, damit keine Verbindung zu Dritten entsteht.' 'Determines the public IP address via api.ipify.org or ifconfig.me (third parties). Off by default, so that no connection to third parties is made.'))
    $tt.SetToolTip($cbLat,(G 'Misst die Antwortzeit zum Internet per Ping an www.google.de bzw. www.devicentra.de. Standardmäßig aus; die Ziele sehen deine IP-Adresse.' 'Measures the response time to the internet via ping to www.google.de or www.devicentra.de. Off by default; the targets see your IP address.'))
    $tt.SetToolTip($cbSpeed,(G 'Lädt eine 10-MB-Datei von crusadersoft.com und misst den Durchsatz. Es wird nichts hochgeladen. Standardmäßig aus (Datenvolumen, Server-Log mit deiner IP).' 'Downloads a 10 MB file from crusadersoft.com and measures the throughput. Nothing is uploaded. Off by default (data volume, server log with your IP).'))
    $tt.SetToolTip($btnLang,(G 'Oberfläche und Konsolenausgabe auf Englisch umstellen. Der HTML-Report enthält immer beide Sprachen.' 'Switch the window and console output to German. The HTML report always contains both languages.'))
    $tt.SetToolTip($btnStart,(G 'Startet den Scan als eigenen Prozess. Der Bericht öffnet sich danach im Browser.' 'Starts the scan as a separate process. The report then opens in the browser.'))
    $tt.SetToolTip($btnHtml,(G 'Öffnet den neuesten Bericht. Im Bericht gibt es oben Knöpfe zum Drucken bzw. Speichern als PDF.' 'Opens the newest report. At the top of the report there are buttons to print or save as PDF.'))

    # Zustand (nur UI-Thread greift darauf zu -> keine Thread-Sync nötig)
    $script:proc       = $null
    $script:finished   = $false
    $script:inTick     = $false
    $script:statusPath = [System.IO.Path]::GetTempFileName()
    $script:lastCount  = 0
    $script:reportPath = ''

    function Add-Log([string]$text,$color) {
        $logbox.SelectionStart=$logbox.TextLength; $logbox.SelectionColor=$color
        $logbox.AppendText("$text`r`n"); $logbox.SelectionColor=$cText; $logbox.ScrollToCaret()
    }
    function Set-Stage([string]$key,[string]$state) {
        $lbl=$stageLabels[$key]; if (-not $lbl) { return }
        if ($state -eq 'run')  { $lbl.Text="$gRun   $($stages[$key])";  $lbl.ForeColor=$cBlue; $lbl.Font=$fStageOn }
        if ($state -eq 'done') { $lbl.Text="$gDone   $($stages[$key])"; $lbl.ForeColor=$cGrn;  $lbl.Font=$fStage }
        if ($state -eq 'idle') { $lbl.Text="$gIdle   $($stages[$key])"; $lbl.ForeColor=$cMut;  $lbl.Font=$fStage }
    }
    # Fortschrittsbalken (Panel-Füllung) + Prozentanzeige
    function Set-Progress([int]$v) {
        if ($v -lt 0) { $v = 0 }; if ($v -gt 100) { $v = 100 }
        $pbFill.Width = [int][Math]::Round($pb.Width * $v / 100.0)
        $pctLbl.Text = "$v %"
    }
    function Find-LatestReport {
        try {
            $dir = Join-Path $env:USERPROFILE "CVEwatch\assets\$env:COMPUTERNAME"
            if (Test-Path $dir) {
                $f = Get-ChildItem $dir -Filter '*.report.html' -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($f) { return $f.FullName }
            }
        } catch {}
        return ''
    }
    # Neueste Datei eines Typs finden und den passenden Export-Knopf (de)aktivieren.
    function Set-ExportBtn($btn, [string]$filter) {
        $path = ''
        try {
            $dir = Join-Path $env:USERPROFILE "CVEwatch\assets\$env:COMPUTERNAME"
            if (Test-Path $dir) {
                $f = Get-ChildItem $dir -Filter $filter -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($f) { $path = $f.FullName }
            }
        } catch {}
        $btn.Tag = $path
        $btn.Enabled = [bool]$path
    }
    function Update-ExportButtons {
        Set-ExportBtn $btnHtml '*.report.html'
        Set-ExportBtn $btnCsv  '*.csv'
        Set-ExportBtn $btnJson '*.matches.json'
        Set-ExportBtn $btnLog  '*.log'
    }
    function Finish-Run {
        $timer.Stop()
        if ($script:finished) { Add-Log (G 'Hinweis: Der Abschluss wurde erneut ausgelöst und ignoriert (Report nicht doppelt geöffnet).' 'Note: completion was triggered again and ignored (report not opened twice).') $cMut; return }   # nur EIN Abschluss je Lauf
        $script:finished = $true
        try { if ($script:proc) { $script:proc.Dispose() } } catch {}
        $script:proc = $null                 # Tick prüft HasExited nicht mehr, der Abschluss kann nicht erneut ausgelöst werden
        # Letzte Zeilen der Status-Datei nachlesen (das Kind kann nach dem letzten Tick noch 'reportpath' geschrieben haben)
        try { foreach ($ln in @(Get-Content -LiteralPath $script:statusPath -EA SilentlyContinue)) { if ("$ln" -like "reportpath`t*") { $script:reportPath = (("$ln" -split "`t", 2)[1]).Trim() }; if ("$ln" -like "summary`t*") { $script:summaryLine = (("$ln" -split "`t", 2)[1]) } } } catch {}
        foreach ($k in $stageOrder) { Set-Stage $k 'done' }
        Set-Progress 100
        if (-not $script:reportPath) { $script:reportPath = Find-LatestReport }
        if ($script:reportPath -and (Test-Path $script:reportPath)) {
            $status.Text=(G 'Fertig. Report wird geöffnet.' 'Done. Opening report.'); $status.ForeColor=$cGrn
            if ($script:summaryLine -match 'nvd_skipped=([1-9]\d*)') { $status.Text=(G "Fertig, aber UNVOLLSTÄNDIG: $($Matches[1]) CVEs fehlen noch. Bitte erneut scannen (oder NVD-Limit abschalten)." "Done, but INCOMPLETE: $($Matches[1]) CVEs are still missing. Please scan again (or switch off the NVD limit)."); $status.ForeColor=$cAmber }
            try { Start-Process $script:reportPath } catch { Add-Log ((G 'Konnte Report nicht öffnen: ' 'Could not open report: ') + $_.Exception.Message) $cRed }
        } else {
            $status.Text=(G 'Lauf beendet, aber kein Report gefunden (siehe Log).' 'Run finished, but no report found (see log).'); $status.ForeColor=$cMut
        }
        Update-ExportButtons
        $btnStart.Enabled=$true; $btnLang.Enabled=$true; $btnStart.Text=(G 'Erneut scannen' 'Scan again')
    }

    # Fortschritt aus der Status-Datei lesen (token<TAB>nachricht je Zeile)
    $timer=New-Object System.Windows.Forms.Timer; $timer.Interval=250
    $timer.Add_Tick({
        if ($script:inTick) { return }       # kein verschachtelter Tick, falls ein Aufruf in der Verarbeitung Nachrichten abarbeitet
        $script:inTick = $true
        try {
        $lines = @(Get-Content -LiteralPath $script:statusPath -EA SilentlyContinue)
        if ($lines.Count -gt $script:lastCount) {
            for ($i=$script:lastCount; $i -lt $lines.Count; $i++) {
                $ln = [string]$lines[$i]; if (-not $ln.Trim()) { continue }
                $parts = $ln -split "`t", 2
                $tok = $parts[0]; $msg = if ($parts.Count -gt 1) { $parts[1] } else { '' }
                if ($tok -eq 'reportpath') { $script:reportPath = $msg.Trim(); continue }
                if ($tok -eq 'summary')    { $script:summaryLine = $msg }
                if ($tok -eq 'done')       { continue }
                if ($tok -eq 'nvdbulk') {   # NVD-Sammelabruf (ab 4.1): erste Hälfte der NVD-Stufe, Format geladen|gesamt|full/incr
                    $pp = $msg -split '\|'
                    if ($pp.Count -ge 3) {
                        $script:nvdBulkSeen = $true
                        $d = [int]$pp[0]; $tot = [int]$pp[1]; $incr = ($pp[2] -eq 'incr')
                        $i0 = [array]::IndexOf($stageOrder,'nvd')
                        if ($i0 -ge 0) {
                            $lo = ($i0/$stageOrder.Count)*100; $hi = (($i0+1)/$stageOrder.Count)*100
                            $f = if ($tot -gt 0) { [Math]::Min(1.0, $d/$tot) } else { 0.0 }
                            Set-Progress ([Math]::Min(95,[int]($lo + ($hi-$lo)*0.5*$f)))
                        }
                        $status.Text = if ($incr) { (G 'NVD-Sammelabruf: hole Änderungen seit dem letzten Lauf ...' 'NVD bulk sync: fetching changes since the last run ...') }
                                       elseif ($tot -gt 0) { (G "NVD-Sammelabruf: $d/$tot KEV-CVEs geladen (einmalig einige MB, danach nur noch Änderungen)" "NVD bulk sync: $d/$tot KEV CVEs loaded (a few MB once, afterwards only changes)") }
                                       else { (G 'NVD-Sammelabruf: lade die NVD-Daten aller KEV-CVEs ...' 'NVD bulk sync: downloading the NVD data of all KEV CVEs ...') }
                    }
                    continue
                }
                if ($tok -eq 'nvdprog') {   # Feinfortschritt des NVD-Abgleichs: Balken + Statuszeile
                    $pp = $msg -split '\|'
                    if ($pp.Count -ge 3) {
                        $d = [int]$pp[0]; $tot = [int]$pp[1]; $eta = [int]$pp[2]
                        $i0 = [array]::IndexOf($stageOrder,'nvd')
                        if ($i0 -ge 0 -and $tot -gt 0) {
                            $lo = ($i0/$stageOrder.Count)*100; $hi = (($i0+1)/$stageOrder.Count)*100
                            if ($script:nvdBulkSeen) { $lo = $lo + ($hi-$lo)*0.5 }   # nach dem Sammelabruf: zweite Hälfte der Stufe (Balken springt nicht zurück)
                            Set-Progress ([Math]::Min(95,[int]($lo + ($hi-$lo)*($d/$tot))))
                        }
                        $etaTxt = if ($d -ge $tot) { (G 'fast fertig' 'almost done') } elseif ($eta -ge 60) { (G 'noch ca. {0} Min {1} s' 'about {0} min {1} s left') -f [int][math]::Floor($eta/60), ($eta % 60) } else { (G "noch ca. $eta s" "about $eta s left") }
                        $status.Text = (G "NVD-Abgleich läuft: $d/$tot CVEs, $etaTxt (die NVD begrenzt die Abfragen, das ist normal)" "NVD check running: $d/$tot CVEs, $etaTxt (the NVD rate-limits requests, this is normal)")
                    }
                    continue
                }
                if ($stageLabels.ContainsKey($tok)) {
                    $idx=[array]::IndexOf($stageOrder,$tok)
                    for ($j=0; $j -lt $idx; $j++) { Set-Stage $stageOrder[$j] 'done' }
                    Set-Stage $tok 'run'
                    Set-Progress ([Math]::Min(95,[int](($idx/$stageOrder.Count)*100)))
                }
                $c=$cText
                if ($msg -match '^\[!\]|nicht erreichbar|fehlgeschlagen|unreachable|failed') { $c=$cRed }
                elseif ($msg -match '^\[\*\]') { $c=$cBlue }
                elseif ($msg -match 'NVD:|CVEs|Treffer|Einträge|betroffen|Cache|hits|entries|affected|cache') { $c=$cMut }
                if ($msg) { Add-Log $msg $c }
            }
            $script:lastCount = $lines.Count
        }
        if ($script:proc -and $script:proc.HasExited) { $timer.Stop(); Finish-Run }
        } finally { $script:inTick = $false }
    })

    $btnStart.Add_Click({
        # Ohne Administratorrechte vor dem Start warnen: neu starten, trotzdem scannen oder zurück
        if (-not $isAdminGui -and -not $script:adminAck) {
            $r = [System.Windows.Forms.MessageBox]::Show(
                (G ("Die Anwendung wurde nicht als Administrator gestartet.`r`n`r`n" +
                    "Der Scan läuft trotzdem, ist aber unvollständig: BitLocker-Status, Defender-Ausschlüsse, SSD-Gesundheitswerte sowie Teile der Treiber- und Dienstdaten fehlen.`r`n`r`n" +
                    "Ja = als Administrator neu starten`r`nNein = trotzdem scannen`r`nAbbrechen = zurück") `
                   ("The application was not started as administrator.`r`n`r`n" +
                    "The scan still runs, but is incomplete: BitLocker status, Defender exclusions, SSD health values and parts of the driver and service data are missing.`r`n`r`n" +
                    "Yes = restart as administrator`r`nNo = scan anyway`r`nCancel = back")),
                (G 'Kein Administrator' 'Not administrator'), [System.Windows.Forms.MessageBoxButtons]::YesNoCancel, [System.Windows.Forms.MessageBoxIcon]::Warning)
            if ($r -eq [System.Windows.Forms.DialogResult]::Cancel) { return }
            if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
                if (-not $scriptPath) {
                    [void][System.Windows.Forms.MessageBox]::Show((G 'Der Skriptpfad ist unbekannt (z. B. aus der ISE gestartet). Bitte PowerShell als Administrator öffnen und das Skript erneut starten.' 'The script path is unknown (e.g. started from the ISE). Please open PowerShell as administrator and start the script again.'),(G 'Neustart nicht möglich' 'Restart not possible'))
                    return
                }
                try {
                    Start-Process -FilePath $hostExe -Verb RunAs -ErrorAction Stop -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',"`"$scriptPath`"",'-Gui','-Lang',$script:Lang)
                    $form.Close(); return
                } catch {
                    [void][System.Windows.Forms.MessageBox]::Show((G 'Der Neustart als Administrator wurde abgebrochen oder ist fehlgeschlagen. Du kannst trotzdem ohne Administratorrechte scannen oder das Programm manuell als Administrator starten.' 'The restart as administrator was cancelled or failed. You can still scan without administrator rights or start the program manually as administrator.'),(G 'Neustart nicht erfolgt' 'No restart'))
                    return
                }
            }
            $script:adminAck = $true   # bewusst fortfahren: für diese Sitzung nicht erneut fragen
        }
        $btnStart.Enabled=$false; $btnLang.Enabled=$false; $btnStart.Text=(G 'Läuft ...' 'Running ...'); $logbox.Clear()
        foreach ($k in $stageOrder) { Set-Stage $k 'idle' }
        Set-Progress 0; $status.Text=(G 'Scan läuft ... (das Fenster bleibt bedienbar)' 'Scan running ... (the window stays responsive)'); $status.ForeColor=$cBlue
        $script:reportPath=''; $script:lastCount=0; $script:finished=$false; $script:summaryLine=''; $script:nvdBulkSeen=$false
        try { '' | Out-File -LiteralPath $script:statusPath -Encoding UTF8 } catch {}

        $psArgs=@('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$scriptPath`"",'-NoOpen','-StatusFile',"`"$($script:statusPath)`"",'-Lang',$script:Lang)
        if (-not $cbKev.Checked) { $psArgs+='-NoKev' }
        elseif (-not $cbVer.Checked) { $psArgs+='-NoVersionCheck' }
        elseif (-not $cbOs.Checked)  { $psArgs+='-NoOsCheck' }
        if (-not $cbLimit.Checked)   { $psArgs+='-NoNvdLimit' }
        if ($cbCache.Checked)    { $psArgs+='-UseCache' }
        if ($cbIP.Checked)    { $psArgs+='-PublicIP' }
        if ($cbLat.Checked)   { $psArgs+='-Latency' }
        if ($cbSpeed.Checked) { $psArgs+='-SpeedTest' }
        # Key per Umgebungsvariable statt Kommandozeile (Argumente sind in der Prozessliste für andere sichtbar)
        if ($tbKey.Text.Trim())  { $env:CVEWATCH_NVD_API_KEY = $tbKey.Text.Trim() }

        $psi=New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName=$hostExe; $psi.Arguments=($psArgs -join ' ')
        $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true   # kein Redirect -> kein Deadlock, Fortschritt via Status-Datei
        $p=New-Object System.Diagnostics.Process; $p.StartInfo=$psi
        try {
            $p.Start()|Out-Null
            $script:proc=$p; $timer.Start()
            Add-Log (G 'Scan gestartet. Beim ersten Lauf lädt der NVD-Abgleich einmalig die Daten aller KEV-CVEs (einige MB), danach nur noch Änderungen.' 'Scan started. On the first run the NVD check downloads the data of all KEV CVEs once (a few MB), afterwards only changes.') $cMut
        } catch {
            Add-Log ((G 'Konnte Scan-Prozess nicht starten: ' 'Could not start scan process: ') + $_.Exception.Message) $cRed
            $btnStart.Enabled=$true; $btnStart.Text=(G 'Scan starten' 'Start scan')
        } finally {
            Remove-Item Env:\CVEWATCH_NVD_API_KEY -EA SilentlyContinue   # Key nur an den Kindprozess vererben, auch bei Fehlschlag aufräumen
        }
    })

    $btnHtml.Add_Click({ if ($btnHtml.Tag) { Start-Process $btnHtml.Tag } })
    $btnCsv.Add_Click({  if ($btnCsv.Tag)  { Start-Process $btnCsv.Tag  } })
    $btnJson.Add_Click({ if ($btnJson.Tag) { Start-Process $btnJson.Tag } })
    $btnLog.Add_Click({  if ($btnLog.Tag)  { Start-Process $btnLog.Tag  } })
    $btnHelp.Add_Click({ Show-CVEwatchHelp $cBg $cSurf $cSurf2 $cText $cMut $cBlue })
    $form.Add_FormClosed({ try { if (Test-Path $script:statusPath) { Remove-Item $script:statusPath -Force -EA SilentlyContinue } } catch {} })

    Update-ExportButtons   # vorhandene Berichte gleich beim Öffnen anbieten
    Add-Log (G 'Bereit. "Scan starten" klicken - der Scan läuft als eigener Prozess, das Fenster bleibt bedienbar.' 'Ready. Click "Start scan" - the scan runs as a separate process, the window stays responsive.') $cMut
    [void]$form.ShowDialog()
}

if ($Gui) {
    # Der Sprachknopf schließt das Fenster und setzt GuiRestart: dann in der neuen Sprache neu aufbauen
    do { $script:GuiRestart = $false; Show-CVEwatchGui } while ($script:GuiRestart)
    return
}

#endregion

#region ============================ KONFIGURATION ============================

# Als SYSTEM (z. B. Intune, SCCM, geplanter Task) nach ProgramData statt ins versteckte Systemprofil schreiben
$RunAsSystem = $false; try { $RunAsSystem = [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem } catch {}
$WorkRoot   = if ($RunAsSystem) { "$env:ProgramData\CVEwatch\assets" } else { "$env:USERPROFILE\CVEwatch\assets" }

# KEV-Quelle: ausschließlich die offizielle CISA-Erstquelle (keine Dritt-Mirror -
# Vertrauenskette zur Datenquelle ist Teil des Produkts). Bei Ausfall greift der lokale Cache.
$KevSources = @(
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
)

$PingTargets        = @('www.google.de','www.devicentra.de')   # nur mit -Latency (Opt-in)
# Tests nach außen sind Opt-in (Datenschutz durch Voreinstellung). -External schaltet alle drei ein.
if ($External) { $PublicIP = $true; $Latency = $true; $SpeedTest = $true }
$PrivacyUrl = 'https://crusadersoft.com/#datenschutz'
$OutgoingIPSources  = @('https://api.ipify.org','https://ifconfig.me/ip')

# Download-Speedtest: Testdatei auf crusadersoft.com. Gemessen wird die tatsächlich geladene
# Byte-Menge, die Dateigröße ist also frei wählbar. Nur mit -SpeedTest / GUI-Option (Opt-in).
$SpeedTestUrl        = 'https://crusadersoft.com/testfiles/testfile10.bin'
$SpeedTestTimeoutSec = 30
$PingDelay = 1; $PingCount = 3

$HostName    = $env:COMPUTERNAME
$ScanStamp   = (Get-Date).ToString('_HHmmss_ddMMyy')
$HostDir     = Join-Path $WorkRoot $HostName
if (-not (Test-Path $HostDir)) { New-Item -ItemType Directory -Path $HostDir -Force | Out-Null }
# Unter ProgramData wären die Reports (Schwachstellenliste, Benutzerkonten, IP/MAC) für alle lokalen Benutzer lesbar:
# als SYSTEM die Vererbung kappen und nur SYSTEM + Administratoren Zugriff geben (SIDs, damit sprachunabhängig)
if ($RunAsSystem) {
    try { & icacls.exe $WorkRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C /Q 2>&1 | Out-Null } catch {}
}

$CsvPath     = Join-Path $HostDir "$HostName$ScanStamp.csv"
$LogPath     = Join-Path $HostDir "$HostName$ScanStamp.log"
$MatchPath   = Join-Path $HostDir "$HostName$ScanStamp.matches.json"
$ReportPath  = Join-Path $HostDir "$HostName$ScanStamp.report.html"
$StatePath   = Join-Path $HostDir 'last_state.json'   # Stand des letzten Laufs (für Diff "neu seit ...")
$KevCache    = Join-Path $WorkRoot 'kev_catalog.json'
$KevCacheTtlHours = 24        # KEV wird täglich aktualisiert -> Cache 24h vorhalten

# --- Versionsabgleich (NVD CPE) ---
# Zieht für die bereits gematchten CVEs die Versionsbereiche aus der NVD und
# vergleicht sie mit der installierten Version -> "betroffen / vermutlich gepatcht".
$ResolveVersions = -not $NoVersionCheck          # per -NoVersionCheck abschaltbar
# $NvdApiKey kommt aus dem param()-Block (optional) oder aus der Umgebungsvariable CVEWATCH_NVD_API_KEY (GUI)
if (-not $NvdApiKey -and $env:CVEWATCH_NVD_API_KEY) { $NvdApiKey = $env:CVEWATCH_NVD_API_KEY }
$NvdCache        = Join-Path $WorkRoot 'nvd_cache_v2.json'      # ab 4.1 kompaktes Format (Feld c) -> eigener Dateiname, damit ältere Versionen ihn nicht falsch lesen
$NvdCacheLegacy  = Join-Path $WorkRoot 'nvd_cpe_cache.json'     # Format bis 4.0.1 (Feld r); wird nur gelesen (einmalige Übernahme), nie geschrieben
$NvdCacheTtlDays = 30         # CPE-Bereiche für bekannte CVEs sind stabil -> 30 Tage vorhalten
$NvdSyncFile     = Join-Path $WorkRoot 'nvd_kev_sync.json'   # Stand des NVD-Sammelabrufs (lastSync / lastFull, UTC)
$NvdBulk         = $true      # NVD-Daten aller KEV-CVEs gesammelt holen (cves/2.0?hasKev), danach nur Änderungen
$NvdBulkPageSize = 500        # CVEs pro Seite beim Sammelabruf (NVD-Maximum 2000; kleinere Seiten = robuster gegen 503 und schneller in PS 5.1)
$NvdBulkFullDays = 30         # spätestens nach so vielen Tagen komplett neu laden statt nur Änderungen (Hygiene)
if ($NoNvdLimit -or $NvdMaxCves -le 0) { $NvdMaxCves = [int]::MaxValue }   # Limit echter NVD-Abfragen pro Lauf: Standard 150 (-NvdMaxCves); -NoNvdLimit = unbegrenzt (Cache-Treffer zählen nie)
$script:NvdSkippedCves = @()   # CVEs, die wegen des Limits in diesem Lauf nicht gegen die NVD geprüft wurden
$NvdStaleOkDays  = 120        # CPE-Bereiche von KEV-CVEs, die schon länger als so viele Tage im KEV stehen, dürfen auch ohne -UseCache aus dem Cache kommen (0 = immer frisch)
$script:NvdDelayMs = if ($NvdApiKey) { 700 } else { 6500 }   # Rate-Limit: 50 bzw. 5 pro 30s
$NvdMaxAttempts  = 3          # Wiederholungen pro CVE bei transienten Fehlern (403/503) - NVD 2.0 ist notorisch flaky
$script:NvdRetryBaseSec = 6   # Backoff-Basis in Sekunden (6, 12 ...)
$NvdCircuitBreak = 5          # so viele Fehler am Stück -> Versionsabgleich abbrechen (NVD down/blockt)

#endregion

#region ============================ HILFSFUNKTIONEN ==========================

function Enc([string]$s) {
    if ($null -eq $s) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($s)
}

# Hover-Erklärungen: <span class='tip' data-tip-de='...' data-tip-en='...'> zeigt beim Überfahren (oder per Tab-Taste) die Erklärung
# in der aktuell im Report gewählten Sprache; die Anzeige übernimmt ein kleines Skript im Report.
function Get-TipAttr($Text) {
    if (Test-L $Text) { "data-tip-de='$(Enc $Text.de)' data-tip-en='$(Enc $Text.en)'" } else { "data-tip-de='$(Enc "$Text")' data-tip-en='$(Enc "$Text")'" }
}
function Tip([string]$LabelHtml, $Text) { "<span class='tip' tabindex='0' $(Get-TipAttr $Text)>$LabelHtml</span>" }
function Pill([string]$Cls, [string]$LabelHtml, $Text) { "<span class='$Cls tip' tabindex='0' $(Get-TipAttr $Text)>$LabelHtml</span>" }
$script:Tips = @{
    'CVE'         = (L 'Eindeutige Kennung einer Sicherheitslücke (CVE-Jahr-Nummer). Ein Klick öffnet die Details bei der NVD, der US-Schwachstellendatenbank.' 'Unique identifier of a vulnerability (CVE-year-number). A click opens the details at the NVD, the US vulnerability database.')
    'KEV'         = (L 'CISA-Katalog „Known Exploited Vulnerabilities": Schwachstellen, die nachweislich in echten Angriffen ausgenutzt werden. Ein Treffer ist dringlicher als eine normale CVE.' 'CISA catalog "Known Exploited Vulnerabilities": vulnerabilities that are known to be exploited in real attacks. A hit is more urgent than a normal CVE.')
    'CVSS'        = (L 'Schweregrad der Lücke von 0 bis 10 (ab 9 kritisch, ab 7 hoch, ab 4 mittel). Er sagt, wie schlimm die Lücke technisch ist, nicht, ob sie bei dir ausgenutzt wird. Dass sie ausgenutzt wird, steht durch den KEV-Eintrag bereits fest.' 'Severity of the vulnerability from 0 to 10 (9+ critical, 7+ high, 4+ medium). It says how bad the vulnerability is technically, not whether it is exploited on your device. That it is exploited is already established by the KEV entry.')
    'Konfidenz'   = (L 'Wie sicher die Zuordnung zwischen installiertem Programm und KEV-Eintrag ist. Hoch: Produkt und Hersteller passen. Mittel: nur der Produktname passt (Fehlzuordnung möglich).' 'How reliable the match between the installed program and the KEV entry is. High: product and vendor match. Medium: only the product name matches (mismatch possible).')
    'Zuordnung'   = (L 'Oben: wie sicher das Programm dem KEV-Eintrag zugeordnet ist. Darunter: deine installierte Version, die verwundbaren Versionsbereiche laut NVD und das Ergebnis des Versionsvergleichs.' 'Top: how reliably the program is matched to the KEV entry. Below: your installed version, the vulnerable version ranges according to the NVD and the result of the version comparison.')
    'Installiert' = (L 'Die auf diesem Rechner installierte Version (bei Windows: der vollständige Build).' 'The version installed on this computer (for Windows: the full build).')
    'Betroffen'   = (L 'Die verwundbaren Versionsbereiche laut NVD. Ein rot markierter Bereich enthält deine Version. „< 2.4" heißt: alle Versionen unterhalb von 2.4.' 'The vulnerable version ranges according to the NVD. A range marked red contains your version. "< 2.4" means: all versions below 2.4.')
    'Behoben'     = (L 'Ab dieser Version ist die Lücke laut NVD behoben. Aktualisiere mindestens auf diese Version.' 'According to the NVD the vulnerability is fixed from this version. Update to at least this version.')
    'Frist'       = (L 'CISA-Fälligkeitsdatum: bis dahin müssen US-Bundesbehörden die Lücke schließen. Eine gute Orientierung für die eigene Dringlichkeit. „Überfällig" heißt: Die Frist ist längst abgelaufen.' 'CISA due date: US federal agencies must close the vulnerability by then. A good guide for your own urgency. "Overdue" means: the due date has long passed.')
    'Ransomware'  = (L 'CISA kennt Erpressergruppen, die diese Lücke für Ransomware-Angriffe nutzen. Das macht den Treffer besonders dringlich.' 'CISA knows of extortion groups that use this vulnerability for ransomware attacks. This makes the hit particularly urgent.')
    'NEU'         = (L 'Dieser Treffer war beim letzten Scan dieses Rechners noch nicht vorhanden.' 'This hit was not present in the last scan of this computer.')
    'V_Betroffen' = (L 'Deine Version liegt laut NVD im verwundbaren Bereich: Die Lücke ist auf diesem Rechner bestätigt offen. Aktualisieren oder entfernen.' 'According to the NVD your version is in the vulnerable range: the vulnerability is confirmed open on this computer. Update or remove.')
    'V_Gepatcht'  = (L 'Deine Version liegt oberhalb der Fix-Grenze der NVD: Die Lücke ist vermutlich behoben. „Vermutlich", weil die NVD-Angaben nicht immer vollständig sind.' 'Your version is above the NVD fix boundary: the vulnerability is probably fixed. "Probably", because the NVD data is not always complete.')
    'V_Unklar'    = (L 'Die NVD-Angaben reichen für keine sichere Aussage (z. B. keine Versionsgrenze oder anderes Produkt). Die Begründung steht darunter; bitte manuell prüfen.' 'The NVD data is not sufficient for a reliable statement (e.g. no version boundary or a different product). The reason is shown below; please check manually.')
    'Schwachstelle' = (L 'Beschreibung und empfohlene Abhilfe stammen von CISA (Englisch). Lange Beschreibungen sind gekürzt und per „mehr" aufklappbar.' 'Description and required action come from CISA. Long descriptions are shortened and can be expanded via "more".')
    'Adresse'     = (L '0.0.0.0 bzw. :: heißt: auf allen Netzwerkkarten erreichbar (WLAN, LAN, VPN). Eine konkrete IP-Adresse: nur in diesem einen Netz.' '0.0.0.0 or :: means: reachable on all network adapters (Wi-Fi, LAN, VPN). A specific IP address: only in that one network.')
}
function TipK([string]$LabelHtml, [string]$Key) { if ($script:Tips.ContainsKey($Key)) { Tip $LabelHtml $script:Tips[$Key] } else { $LabelHtml } }
function PillK([string]$Cls, [string]$LabelHtml, [string]$Key) { if ($script:Tips.ContainsKey($Key)) { Pill $Cls $LabelHtml $script:Tips[$Key] } else { "<span class='$Cls'>$LabelHtml</span>" } }

# Zweisprachige Ausgabe im Report: beide Sprachen im HTML, ein Umschalter blendet eine davon aus (CSS-Klassen l-de / l-en)
function B([string]$de, [string]$en) { if ($de -ceq $en) { return (Enc $de) }; "<span class='l-de'>$(Enc $de)</span><span class='l-en'>$(Enc $en)</span>" }
function BH([string]$deHtml, [string]$enHtml) { if ($deHtml -ceq $enHtml) { return $deHtml }; "<span class='l-de'>$deHtml</span><span class='l-en'>$enHtml</span>" }
function V($v) { if (Test-L $v) { B $v.de $v.en } else { Enc "$v" } }

# Fortschritt: auf die Konsole schreiben UND (für die GUI) als Token in die Status-Datei.
function Emit([string]$stageToken, [string]$msg, $color = 'Cyan') {
    Write-Host $msg -ForegroundColor $color
    if ($StatusFile) { try { "$stageToken`t$msg" | Out-File -FilePath $StatusFile -Append -Encoding UTF8 } catch {} }
}
# Restzeit lesbar ("3 Min 20 s")
function Format-Eta([int]$sec, [string]$In = $script:Lang) {
    $de = ($In -eq 'de')
    if ($sec -lt 5)  { return $(if ($de) { 'wenige Sekunden' } else { 'a few seconds' }) }
    if ($sec -lt 60) { return "$sec s" }
    $m = [int][math]::Floor($sec / 60); $s = $sec % 60
    if ($m -ge 60) { return ($(if ($de) { '{0} Std {1} Min' } else { '{0} h {1} min' }) -f [int][math]::Floor($m / 60), ($m % 60)) }
    return ($(if ($de) { '{0} Min {1} s' } else { '{0} min {1} s' }) -f $m, $s)
}
# Status-Datei zu Beginn leeren (frischer Lauf)
if ($StatusFile) { try { '' | Out-File -FilePath $StatusFile -Encoding UTF8 } catch {} }

# >>> MATCHER-KERN-START (wird vom Regressionstest geladen)
# Sprach-Helfer auch hier verfügbar machen, falls der Kern allein geladen wird (Regressionstest)
if (-not (Get-Command L -CommandType Function -EA SilentlyContinue)) {
    function L([string]$de, [string]$en) { $o = [pscustomobject]@{ de = $de; en = $en }; $o | Add-Member -MemberType ScriptMethod -Name ToString -Value { $this.de } -Force; $o }
    function Test-L($v) { return ($null -ne $v -and $v -isnot [string] -and $v.PSObject.Properties['de'] -and $v.PSObject.Properties['en']) }
}
# Rausch-Tokens: alleine kein aussagekräftiger Treffer
$script:NoiseTokens = New-Object System.Collections.Generic.HashSet[string]
@(
    'the','and','for','inc','llc','ltd','corp','corporation','gmbh','company',
    'x64','x86','win32','win64','amd64','arm64','bit','32bit','64bit',
    'redistributable','runtime','runtimes','update','updates','edition',
    'version','driver','drivers','software','application','package','packages',
    'microsoft','windows','component','components','service','services',
    'server','client','tool','tools','system','core','common','shared',
    'setup','installer','framework','pack','plus','professional','home','enterprise',
    # generische Produkt-Wörter -> alleine kein aussagekräftiger Treffer
    'media','player','reader','viewer','editor','browser','launcher','helper',
    'manager','center','suite','plugin','connect','express','multimedia','studio'
) | ForEach-Object { [void]$script:NoiseTokens.Add($_) }

# Hersteller-Rauschen: NUR generische Firmen-Suffixe. Anders als beim Produkt-
# Rauschen sind 'microsoft'/'google'/'apache' etc. hier ERWÜNSCHT (Vendor-Match).
$script:VendorNoise = New-Object System.Collections.Generic.HashSet[string]
@(
    'the','and','inc','llc','ltd','corp','corporation','gmbh','company','co',
    'technologies','technology','software','systems','group','limited','labs',
    'international','solutions','sarl','sas','ag','kg','bv','pty'
) | ForEach-Object { [void]$script:VendorNoise.Add($_) }

# Whitelist kurzer, aber eindeutiger Produkt-/Hersteller-Tokens (Länge < 3),
# die trotzdem als aussagekräftig gelten sollen. Hier erweiterbar.
$script:ShortWhitelist = New-Object System.Collections.Generic.HashSet[string]
@( '7z','qt','go','hp','f5','ge','vm','os','ai' ) | ForEach-Object { [void]$script:ShortWhitelist.Add($_) }

# Zerlegt einen Namen in normalisierte Tokens (klein, ohne Versionsnummern)
function Get-Tokens([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return @() }
    $s = $s.ToLowerInvariant() -replace '\+\+','pp' -replace '[^a-z0-9]+',' '     # '++' bleibt unterscheidbar (Notepad++ <> Notepad, C++ -> cpp)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($t in ($s -split '\s+')) {
        if (-not $t) { continue }
        if ($t -match '^\d+$') { continue }          # reine Zahlen (Versionen/Jahre)
        [void]$out.Add($t)
    }
    return $out.ToArray()
}

# STARKE Produkt-Tokens: >= 4 Zeichen, kein Rauschen. Reichen für sich allein.
function Get-StrongTokens([string[]]$tokens) {
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($t in $tokens) {
        if ($t.Length -ge 4 -and -not $script:NoiseTokens.Contains($t)) { [void]$out.Add($t) }
    }
    return ($out | Select-Object -Unique)
}

# SCHWACHE Produkt-Tokens: genau 3 Zeichen (kein Rauschen) oder Whitelist-Kurznamen.
# Diese matchen NUR, wenn zusätzlich der Hersteller passt (Vendor-Gate) -> minimiert False Positives.
function Get-WeakTokens([string[]]$tokens) {
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($t in $tokens) {
        if ($script:ShortWhitelist.Contains($t)) { [void]$out.Add($t); continue }
        if ($t.Length -eq 3 -and -not $script:NoiseTokens.Contains($t)) { [void]$out.Add($t) }
    }
    return ($out | Select-Object -Unique)
}

# Aussagekräftige Hersteller-Tokens (>= 3 Zeichen oder Whitelist, ohne Firmen-Suffixe)
function Get-VendorTokens([string[]]$tokens) {
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($t in $tokens) {
        if ($script:VendorNoise.Contains($t)) { continue }
        if ($t.Length -ge 3 -or $script:ShortWhitelist.Contains($t)) { [void]$out.Add($t) }
    }
    return ($out | Select-Object -Unique)
}

# Kurze Prozessnamen (z. B. "chrome", "msedge") auf den Produktnamen abbilden. Nur EXAKTE Treffer auf den ganzen Namen:
# eine Teilstring-Suche machte früher aus "Adobe Media Encoder" oder "K-Lite Codec Pack" ein "Visual Studio Code"
# und aus "Chrome Remote Desktop Host" ein "Google Chrome" (falsche KEV-Treffer).
$script:SoftwareNameMap = @{
    'chrome'='Google Chrome'; 'msedge'='Microsoft Edge'; 'firefox'='Mozilla Firefox'
    'code'='Visual Studio Code'; 'vscode'='Visual Studio Code'
    'powershell'='Windows PowerShell'; 'pwsh'='PowerShell'
    'python'='Python'; 'python3'='Python'; 'node'='Node.js'; 'nodejs'='Node.js'
}
function Normalize-SoftwareName([string]$name) {
    if ([string]::IsNullOrWhiteSpace($name)) { return $name }
    $key = ($name.Trim().ToLowerInvariant() -replace '\.exe$', '')
    if ($script:SoftwareNameMap.ContainsKey($key)) { return $script:SoftwareNameMap[$key] }
    return $name
}

# --- Versions-Helfer -------------------------------------------------------
# Zerlegt eine Version in ein Integer-Array (führende Nicht-Ziffern/Suffixe ignoriert)
function ConvertTo-VerArray([string]$v) {
    if ([string]::IsNullOrWhiteSpace($v)) { return @() }
    $v = ($v -replace '^[^0-9]*', '')            # z.B. 'v1.2' -> '1.2'
    # Int64 statt Int32: Teile wie '20240101123456' (Datums-/Build-Stempel) sprengten [int] -> Laufzeitfehler und
    # stillschweigend verkürzte Version. Noch längere Teile beenden die Zerlegung wie ein Suffix (kein Fehler).
    $out = New-Object System.Collections.Generic.List[long]
    foreach ($p in ($v -split '[.\-_+ ]')) {
        $m = [regex]::Match($p, '^\d+'); $n = [long]0
        if ($m.Success -and [long]::TryParse($m.Value, [ref]$n)) { [void]$out.Add($n) } else { break }
    }
    return $out.ToArray()
}
# Vergleicht zwei Versionen: -1 / 0 / 1, oder $null wenn nicht vergleichbar
function Compare-Ver($a, $b) {
    $A = @(ConvertTo-VerArray $a); $B = @(ConvertTo-VerArray $b)
    if ($A.Count -eq 0 -or $B.Count -eq 0) { return $null }
    $n = [Math]::Max($A.Count, $B.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $x = if ($i -lt $A.Count) { $A[$i] } else { 0 }
        $y = if ($i -lt $B.Count) { $B[$i] } else { 0 }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    return 0
}
# Liegt die installierte Version im verwundbaren Bereich eines CPE-Match? $true/$false/$null(unklar)
function Test-InVulnRange($installed, $cpe) {
    if ($cpe.Exact) {                             # CPE nennt exakte Version
        $c = Compare-Ver $installed $cpe.Exact
        if ($null -eq $c) { return $null }
        return ($c -eq 0)
    }
    $bounded = $false
    if ($cpe.VSI) { $c = Compare-Ver $installed $cpe.VSI; if ($null -eq $c) { return $null }; if ($c -lt 0) { return $false }; $bounded = $true }
    if ($cpe.VSE) { $c = Compare-Ver $installed $cpe.VSE; if ($null -eq $c) { return $null }; if ($c -le 0) { return $false }; $bounded = $true }
    if ($cpe.VEI) { $c = Compare-Ver $installed $cpe.VEI; if ($null -eq $c) { return $null }; if ($c -gt 0) { return $false }; $bounded = $true }
    if ($cpe.VEE) { $c = Compare-Ver $installed $cpe.VEE; if ($null -eq $c) { return $null }; if ($c -ge 0) { return $false }; $bounded = $true }
    if (-not $bounded) { return $true }           # CPE = Produkt:* ohne Grenzen -> alle Versionen betroffen
    return $true
}
# Verdikt für ein normales Programm anhand der NVD-CPE-Liste. Ein CPE-Eintrag OHNE Versionsgrenze (Produkt:* bzw. Produkt:-)
# heißt nur "die NVD grenzt nicht ein" und wird NIE als "betroffen" gewertet (sonst würden z. B. alte Edge-Einträge oder
# zufällige Namensüberschneidungen als bestätigt verwundbar erscheinen); solche Fälle sind "Unklar".
function Test-AppVerdict([string]$Installed, $Tokens, $Cfg) {
    $r = [PSCustomObject]@{ Class='Unclear'; Verdict='Unklar'; Reason=''; Ranges=@(); Matched=@(); Fixed=@() }
    $relevant = @($Cfg | Where-Object { Test-CpeProductMatch $_.Product $Tokens })
    if ($relevant.Count -eq 0) {
        $np = (@($Cfg | ForEach-Object { $_.Product } | Where-Object { $_ } | Select-Object -Unique -First 3) -join ', ')
        $r.Class = 'OtherProducts'
        $r.Reason = L "Die NVD nennt für diese CVE andere Produkte ($np) - keine eindeutige Zuordnung zu diesem Programm." "The NVD lists other products for this CVE ($np) - no clear match to this program."
        return $r
    }
    $rng = New-Object System.Collections.Generic.List[string]; $hit = New-Object System.Collections.Generic.List[string]
    $fixHit = New-Object System.Collections.Generic.List[string]; $fixAll = New-Object System.Collections.Generic.List[string]
    $anyDet = $false; $anyIn = $false; $anyUnb = $false
    foreach ($cpe in $relevant) {
        $bounded = [bool]($cpe.Exact -or $cpe.VSI -or $cpe.VSE -or $cpe.VEI -or $cpe.VEE)
        $x = if ($bounded) { Test-InVulnRange $Installed $cpe } else { $null }
        if (-not $bounded) { $anyUnb = $true }
        if ($null -ne $x) { $anyDet = $true; if ($x) { $anyIn = $true } }
        $rt = Format-CpeRange $cpe
        if (-not $rng.Contains($rt)) { $rng.Add($rt) }
        if ($x -and -not $hit.Contains($rt)) { $hit.Add($rt) }
        $fx = if ($cpe.VEE) { "ab $($cpe.VEE)" } elseif ($cpe.VEI) { "neuer als $($cpe.VEI)" } else { '' }   # VEE = erste nicht mehr betroffene Version
        if ($fx) { if (-not $fixAll.Contains($fx)) { $fixAll.Add($fx) }; if ($x -and -not $fixHit.Contains($fx)) { $fixHit.Add($fx) } }
    }
    $r.Ranges = @($rng); $r.Matched = @($hit); $r.Fixed = @($(if ($fixHit.Count -gt 0) { $fixHit } else { $fixAll }) | Select-Object -First 3)
    if ($anyDet) {
        if ($anyIn) { $r.Class = 'Affected'; $r.Verdict = 'Betroffen' }
        else { $r.Class = 'Patched'; $r.Verdict = 'Vermutlich gepatcht'; $r.Reason = L 'Die installierte Version liegt außerhalb aller von der NVD genannten verwundbaren Bereiche.' 'The installed version is outside all vulnerable ranges listed by the NVD.' }
    } elseif ($anyUnb) { $r.Class = 'Unbounded'; $r.Reason = L 'Die NVD nennt für diese CVE keine Versionsgrenze für dieses Produkt (alle Versionen bzw. nicht eingegrenzt); ob die installierte Version betroffen ist, lässt sich so nicht sagen.' 'The NVD gives no version boundary for this product for this CVE (all versions or not narrowed down); whether the installed version is affected cannot be determined this way.' }
    else { $r.Reason = L 'Der Versionsvergleich ist nicht möglich (Versionsformat nicht vergleichbar).' 'The version comparison is not possible (version format not comparable).' }
    return $r
}

# Lesbarer Text für den verwundbaren Versionsbereich eines CPE-Match (Anzeige im Report)
function Format-CpeRange($cpe) {
    if ($cpe.Exact) { return ('= {0}' -f $cpe.Exact) }
    $parts = New-Object System.Collections.Generic.List[string]
    if ($cpe.VSI) { $parts.Add(('≥ {0}' -f $cpe.VSI)) }
    if ($cpe.VSE) { $parts.Add(('> {0}' -f $cpe.VSE)) }
    if ($cpe.VEI) { $parts.Add(('≤ {0}' -f $cpe.VEI)) }
    if ($cpe.VEE) { $parts.Add(('< {0}' -f $cpe.VEE)) }
    if ($parts.Count -eq 0) { return 'alle Versionen' }
    return ($parts -join ' und ')
}
# Passt das CPE-Produkt zu unserem installierten Produkt? (Token-Überschneidung)
function Test-CpeProductMatch([string]$cpeProduct, [string[]]$itemTokens) {
    $ct = @(Get-Tokens ($cpeProduct -replace '_', ' '))
    foreach ($t in $ct) { if ($t.Length -ge 3 -and ($itemTokens -contains $t)) { return $true } }
    return $false
}

# ---------------------------------------------------------------------------
# KEV-ABGLEICH: Normalisierungsschicht (Tabellen) + Index + Matcher
# KEV benennt Produkte frei ("Chromium V8", "Firefox and Thunderbird", "Tools"), Windows
# registriert sie anders ("Google Chrome", "win.rar GmbH"). Die Tabellen unten schließen
# bekannte Lücken; sie sind bewusst klein, lesbar und hier erweiterbar. Absicherung durch
# dem Regressionstest (MatchTests) - nach jeder Änderung dort laufen lassen.
# ---------------------------------------------------------------------------

# 1) KEV-Produktregeln: bilden einen KEV-Eintrag auf eine oder mehrere Namensvarianten ab, gegen die
#    das Inventar geprüft wird (erste passende Regel gewinnt).
#      Vendor/Product = Regex auf KEV vendorProject / product
#      As       = Alternativen; JEDE ist ein eigener Index-Eintrag (Treffer, wenn EINE passt)
#      VendorAs = Herstellername für die Gegenprobe, falls KEV einen anderen führt (optional)
#      All      = $true: ALLE Namens-Wörter (auch generische wie 'server') müssen im Programmnamen stehen
#      Not      = Wörter im Programmnamen, die auf ein anderes Produkt hindeuten (z. B. 'code' bei Visual Studio) -> kein Treffer
$script:KevProductRules = @(
    @{ Vendor='^Google$';      Product='^Chrom(e|ium)(?!.*Android)(\s.*)?$';      As=@('Chromium') }                    # V8, Mojo, Blink, FreeType ... = Komponenten desselben Browsers (nicht Android)
    @{ Vendor='^Mozilla$';     Product='^Firefox,? (Firefox ESR,? )?and Thunderbird$'; As=@('Firefox','Thunderbird') }
    @{ Vendor='^Microsoft$';   Product='^Edge and Internet Explorer$';            As=@('Edge','Internet Explorer') }
    @{ Vendor='^Microsoft$';   Product='^\.NET Core and Visual Studio$';          As=@('.NET Core','Visual Studio'); All=$true; Not=@('code') }       # nicht Visual Studio Code
    @{ Vendor='^Microsoft$';   Product='^\.NET Framework, SharePoint, Visual Studio$'; As=@('.NET Framework','SharePoint','Visual Studio'); All=$true; Not=@('code','native') }
    @{ Vendor='^Microsoft$';   Product='^\.NET Framework$';                        As=@('.NET Framework'); All=$true; Not=@('native') }             # nicht .NET Native (UWP-Laufzeit)
    @{ Vendor='^Microsoft$';   Product='^SQL Server$';                             As=@('SQL Server'); Not=@('compact') }                           # nicht SQL Server Compact
    @{ Vendor='^Adobe$';       Product='^Flash Player and AIR$';                  As=@('Flash Player','AIR') }
    @{ Vendor='^Adobe$';       Product='^Acrobat and Reader, Flash Player$';      As=@('Acrobat','Reader','Flash Player') }
    @{ Vendor='^TeamViewer$';  Product='^Desktop$';                               As=@('TeamViewer') }                  # Produktname im KEV ist nur "Desktop"
    @{ Vendor='^VMware$';      Product='^ESXi, Workstation, and Fusion$';         As=@('Workstation','Fusion') }
    @{ Vendor='^VMware$';      Product='^ESXi and Workstation$';                  As=@('Workstation') }
    @{ Vendor='^VMware$';      Product='^Tools$';                                 As=@('VMware Tools'); All=$true }
    @{ Vendor='^Broadcom$';    Product='VMware Tools$';                           As=@('VMware Tools'); VendorAs='VMware'; All=$true }
    @{ Vendor='^Trend Micro$'; Product='^Apex One and OfficeScan$';               As=@('Apex One','OfficeScan') }
    @{ Vendor='^Trend Micro$'; Product='^Apex One( and|, Apex One as a Service, and) Worry-Free Business Security$'; As=@('Apex One','Worry-Free Business Security') }
    @{ Vendor='^PaperCut$';    Product='^(NG/MF|MF/NG)$';                         As=@('PaperCut NG','PaperCut MF'); All=$true }
)

# 2) Inventar-Aliase: Programmnamen, die für den Abgleich zusätzliche Namens-Tokens erhalten.
#    Der NVD-Versionsabgleich nutzt weiterhin nur die echten Namens-Tokens.
$script:InvAliasRules = @(
    # Chrome basiert auf Chromium; KEV führt Chrome-Fehler fast ausschließlich unter "Chromium ...".
    # Nicht für Chrome Remote Desktop / Updater (andere Versionsnummern).
    @{ Name='^google chrome\b(?!.*\b(remote|updater|frame)\b)'; AddTokens=@('chromium') }
    # Microsoft Edge (und WebView2) basiert auf Chromium; Versionsnummer = Chromium-Hauptversion + eigener Build.
    # CpeProducts = CPE-Produkte, unter denen die NVD Edge führt; Chromium = Verdikt per Test-ChromiumBaseVerdict.
    @{ Name='^microsoft edge\b(?!.*\b(update|beta|dev|canary)\b)'; AddTokens=@('chromium'); CpeProducts=@('edge_chromium','edge'); Chromium=$true }
)

# 2b) Programme ohne eigenen KEV-Bezug: teilen nur den Namen mit einem Produkt (z. B. der Updater von Edge ist kein Browser).
$script:InvIgnoreRules = @(
    '^microsoft edge update\b'
    '^microsoft\.(net\.native|vclibs|ui\.xaml|windowsappruntime|directx)'     # Windows-Laufzeitpakete (AppX): keine eigenständigen KEV-Produkte
    '\.net native\b'
)
# Wörter, die als EINZIGES Produktwort zu allgemein sind ("Configuration Manager" darf nicht auf "Input Configuration Device" treffen):
# dann müssen alle Wörter des KEV-Produkts im Programmnamen stehen, und der Hersteller muss passen.
$script:GenericProductTokens = @('configuration','http','firewall','kernel','central','router','routers','desktop','device','devices','core','viewer','console','agent','gateway','platform','security','management','access','remote','control','center')

# 3) Hersteller-Aliase: Publisher-/Programmname -> zusätzliche Hersteller-Tokens für die Gegenprobe.
$script:VendorAliasRules = @(
    @{ Pattern='win\.?rar|rarlab'; Add=@('rarlab') }      # Publisher "win.rar GmbH", KEV-Hersteller "RARLAB"
    @{ Pattern='^microsoft edge\b'; Add=@('google') }     # Chromium-Fehler stehen im KEV unter Hersteller "Google"
)

# Ein KEV-Eintrag -> 0..n Index-Einträge (nach Regeln, sonst direkt bzw. mit Herstellername)
function Expand-KevEntry($v) {
    $ven = ([string]$v.vendorProject).Trim(); $prod = ([string]$v.product).Trim()
    # Windows selbst (nicht per Programmname, sondern per Build abgleichbar): als OS-Eintrag indexieren
    if ($ven -eq 'Microsoft' -and $prod -match $script:OsKevProductRegex) {
        $script:KevStats.OsEntries++
        return ,[PSCustomObject]@{
            IsOs=$true; CVE=$v.cveID; Vendor=$v.vendorProject; Product=$prod; Name=$v.vulnerabilityName
            Year=[int](([string]$v.cveID -split '-')[1]); Added=$v.dateAdded; Due=$v.dueDate
            Ransom=($v.knownRansomwareCampaignUse -eq 'Known'); Desc=$v.shortDescription; Action=$v.requiredAction
            Strong=@(); Weak=@(); All=@(); VSig=@()
        }
    }
    $alts = $null; $vendAs = $ven; $reqAll = $false; $notT = @(); $needV = $false
    foreach ($r in $script:KevProductRules) {
        if ($ven -match $r.Vendor -and $prod -match $r.Product) {
            $alts = @($r.As); if ($r.VendorAs) { $vendAs = $r.VendorAs }; $reqAll = [bool]$r.All; if ($r.Not) { $notT = @($r.Not) }; break
        }
    }
    if (-not $alts) {
        $pt = @(Get-Tokens $prod); $sT = @(Get-StrongTokens $pt); $wT = @(Get-WeakTokens $pt)
        if ($sT.Count -eq 1 -and $wT.Count -eq 0 -and $script:GenericProductTokens -contains $sT[0]) {
            $alts = @($prod); $reqAll = $true; $needV = $true          # nur ein allgemeines Wort: alle Wörter + passender Hersteller nötig
        } elseif ($sT.Count -eq 0 -and $wT.Count -eq 0) {
            # Nur generische Wörter ("Server", "Reader", "Media Server"): Herstellername dazunehmen, alle Wörter müssen passen
            $alts = @("$ven $prod"); $reqAll = $true
        } else { $alts = @($prod) }
    }
    foreach ($alt in $alts) {
        $pTok   = @(Get-Tokens $alt)
        $strong = @(Get-StrongTokens $pTok)
        $weak   = @(Get-WeakTokens   $pTok)
        $reqThis = $reqAll
        if ($strong.Count -eq 0 -and $weak.Count -eq 0) {               # z.B. Alternative "Reader": Herstellername davor, alle Wörter müssen passen
            $pTok = @(Get-Tokens "$vendAs $alt"); $strong = @(Get-StrongTokens $pTok); $weak = @(Get-WeakTokens $pTok); $reqThis = $true
            if ($strong.Count -eq 0 -and $weak.Count -eq 0) { continue }
        }
        $all = if ($reqThis) { @($pTok | Select-Object -Unique) } else { @($strong + $weak | Select-Object -Unique) }
        [PSCustomObject]@{
            CVE=$v.cveID; Vendor=$v.vendorProject; Product=$v.product
            Name=$v.vulnerabilityName; Added=$v.dateAdded; Due=$v.dueDate
            Ransom=($v.knownRansomwareCampaignUse -eq 'Known')
            Desc=$v.shortDescription; Action=$v.requiredAction
            Strong=$strong; Weak=$weak; All=$all; Not=$notT; NeedVendor=$needV
            VSig=@(Get-VendorTokens (Get-Tokens $vendAs))
        }
    }
}

# KEV-Index aufbauen. Strong = starke Produkt-Tokens (>=4, matchen für sich), Weak = 3 Zeichen/Whitelist
# (nur mit Hersteller), VSig = aussagekräftige Hersteller-Tokens. Statistik in $script:KevStats.
function Build-KevIndex($vulns) {
    $script:KevStats = @{ Total = 0; Indexed = 0; OsEntries = 0; Unmatchable = 0 }
    $idx = New-Object System.Collections.Generic.List[object]
    foreach ($v in @($vulns)) {
        $script:KevStats.Total++
        $es = @(Expand-KevEntry $v)
        if ($es.Count -eq 0) { $script:KevStats.Unmatchable++; continue }
        if (-not $es[0].IsOs) { $script:KevStats.Indexed++ }      # OS-Einträge zählt Expand-KevEntry in OsEntries
        foreach ($e in $es) { $idx.Add($e) }
    }
    return ,$idx
}

# Inventar-Eintrag für den Abgleich (Aliase eingerechnet). Tokens = echte Namens-Tokens (für NVD-Stufe),
# MatchTokens = Tokens + Aliase (nur für KEV), VendorTokens = Name + Publisher + Hersteller-Aliase.
function New-MatchItem([string]$Name, [string]$Version, [string]$Manufacturer, [string]$Source) {
    $tok = @(Get-Tokens $Name)
    $mt  = New-Object System.Collections.Generic.List[string]; foreach ($t in $tok) { $mt.Add($t) }
    $ln  = $Name.ToLowerInvariant()
    $ignore = $false; foreach ($ir in $script:InvIgnoreRules) { if ($ln -match $ir) { $ignore = $true } }
    $cpeProd = @(); $chromBase = $false
    foreach ($r in $script:InvAliasRules) {
        if ($ln -match $r.Name) {
            foreach ($a in $r.AddTokens) { if (-not $mt.Contains($a)) { $mt.Add($a) } }
            if ($r.CpeProducts) { $cpeProd = @($r.CpeProducts) }
            if ($r.Chromium) { $chromBase = $true }
        }
    }
    $vt  = New-Object System.Collections.Generic.List[string]; foreach ($t in @(Get-Tokens ($Name + ' ' + $Manufacturer))) { $vt.Add($t) }
    $vs  = ($Name + ' ' + $Manufacturer).ToLowerInvariant()
    foreach ($r in $script:VendorAliasRules) { if ($vs -match $r.Pattern) { foreach ($a in $r.Add) { if (-not $vt.Contains($a)) { $vt.Add($a) } } } }
    $mf  = New-Object System.Collections.Generic.List[string]; foreach ($t in @(Get-VendorTokens (Get-Tokens $Manufacturer))) { $mf.Add($t) }
    $ms  = $Manufacturer.ToLowerInvariant()
    foreach ($r in $script:VendorAliasRules) { if ($ms -match $r.Pattern) { foreach ($a in $r.Add) { if (-not $mf.Contains($a)) { $mf.Add($a) } } } }
    [PSCustomObject]@{ Name=$Name; Version=$Version; Source=$Source; Tokens=$tok; MatchTokens=$mt.ToArray(); VendorTokens=$vt.ToArray(); MfrTokens=$mf.ToArray(); CpeProducts=$cpeProd; ChromiumBase=$chromBase; Ignore=$ignore; C2R=[bool](($ln -match $script:C2RNameRegex) -and ($Version -match '^16\.0\.\d{5}\.\d+')); Hits=(New-Object System.Collections.Generic.List[object]) }
}

# KEV-Treffer je Inventar-Eintrag (Hits werden am Eintrag ergänzt)
function Find-KevHits($items, $kevIndex) {
    foreach ($item in $items) {
        if ($item.IsOs -or $item.Ignore) { continue }
        $tokSet  = [System.Collections.Generic.HashSet[string]]::new([string[]]$item.MatchTokens)
        $vendSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$item.VendorTokens)
        $seen    = New-Object System.Collections.Generic.HashSet[string]
        foreach ($ke in $kevIndex) {
            if ($ke.IsOs) { continue }                          # Windows selbst: nur über den Build-Abgleich (Add-OsHits)
            # Kern: ALLE geforderten KEV-Produkt-Tokens müssen als exakte Tokens vorkommen
            $all = $true
            foreach ($d in $ke.All) { if (-not $tokSet.Contains($d)) { $all = $false; break } }
            if (-not $all) { continue }

            # Hersteller-Gegenprobe: passt ein aussagekräftiges KEV-Vendor-Token zum Gerät?
            $vendorOk = $false
            foreach ($vt in $ke.VSig) { if ($vendSet.Contains($vt)) { $vendorOk = $true; break } }

            # Vendor-Gate: Treffer, die auf EINEM einzelnen oder auf einem schwachen Token beruhen
            # (z.B. "zip", "vlc" oder ein einzelnes Wort), gelten NUR mit passendem Hersteller. Nur
            # Produktnamen mit >= 2 Tokens dürfen auch ohne Hersteller matchen.
            $needsVendor = ($ke.All.Count -eq 1) -or ($ke.Weak.Count -gt 0) -or $ke.NeedVendor
            $blocked = $false; foreach ($nt in @($ke.Not)) { if ($nt -and $tokSet.Contains($nt)) { $blocked = $true; break } }
            if ($blocked) { continue }                              # Wort im Programmnamen deutet auf ein anderes Produkt hin
            if ($needsVendor -and -not $vendorOk) { continue }
            # Konflikt: Der Publisher des Programms ist bekannt, passt aber NICHT zum KEV-Hersteller (z.B. "Veeam Backup & Replication"
            # gegen KEV "NAKIVO | Backup and Replication") -> anderes Produkt, kein Treffer. Fehlt der Publisher, bleibt es bei "Mittel".
            if (-not $vendorOk -and @($item.MfrTokens).Count -gt 0) { continue }
            if (-not $seen.Add($ke.CVE)) { continue }       # dieselbe CVE nur einmal je Programm (z.B. Firefox + Firefox ESR)

            if ($vendorOk) { $conf = 'Hoch';   $basis = 'Produkt + Hersteller' }
            else           { $conf = 'Mittel'; $basis = 'Produktname' }
            $item.Hits.Add([PSCustomObject]@{
                CVE=$ke.CVE; Vendor=$ke.Vendor; Product=$ke.Product; Name=$ke.Name
                Added=$ke.Added; Due=$ke.Due; Ransom=$ke.Ransom; Desc=$ke.Desc
                Action=$ke.Action; Confidence=$conf; Basis=$basis
            })
        }
    }
}
# ---------------------------------------------------------------------------
# WINDOWS-BETRIEBSSYSTEM: Build-Abgleich
# KEV-Einträge zu Windows selbst ("Windows", "Win32k", "SMBv3" ...) haben keinen Programmnamen, gegen den man abgleichen
# könnte. Die NVD führt sie aber je Windows-Release (CPE "windows_11_24h2" ...) mit der ersten NICHT mehr betroffenen
# Build-Nummer (versionEndExcluding = "10.0.26100.2894"). Der installierte Build (10.0.<Build>.<UBR>) wird damit verglichen.
# ---------------------------------------------------------------------------

# KEV-Produkte von Microsoft, die zu Windows selbst gehören (abgeleitet aus den NVD-Daten: Einträge mit windows_*-OS-CPE).
$script:OsKevProductRegex = '^(Windows\b.*|Win32k|Active Directory( Federation Services)?|DirectX( Graphics Kernel \(DXGKRNL\))?|Graphics Device Interface \(GDI\)|Enhanced Cryptographic Provider|Internet Key Exchange \(IKE\) Service Extensions|DWM Core Library|SmartScreen Prompt|Streaming Service( Proxy)?|WordPad|Update Notification Manager|HTTP Protocol Stack|Client-Server Run-time Subsystem \(CSRSS\)|Ancillary Function Driver \(afd\.sys\)|Kerberos Key Distribution Center \(KDC\)|Task Scheduler|ATM Font Driver|Graphics Component|SMBv[13].*|HTTP\.sys|WinVerifyTrust function|Remote Desktop Services|Hyper-V RemoteFX|Netlogon|Input Method Editor \(IME\).*|MSHTML( Platform)?|XML Core Services|Office and WordPad)$'

# Alte CVEs, die die NVD trotzdem für aktuelle Windows-Releases führt (nachträglich ergänzt): nie wegfiltern.
$script:OsAlwaysCheck = @('CVE-2013-3900')

# Windows-Releases: Build -> NVD-CPE-Produkt. From = frühestes CVE-Jahr, das die NVD für dieses Release zu "Windows"/"Win32k" führt,
# minus 1 Jahr Sicherheitsabstand (ältere KEV-Einträge werden nicht einzeln gegen die NVD geprüft, spart Abfragen).
# Eol = nicht mehr mit regulären Updates versorgt: die NVD führt dort meist keine Build-Grenzen -> kein belastbarer Abgleich.
$script:OsReleases = @(
    @{ Kind='Client'; Build=10240; Key='windows_10_1507'; Name='Windows 10 1507'; From=2014 }
    @{ Kind='Client'; Build=10586; Key='windows_10_1511'; Name='Windows 10 1511'; From=2015 }
    @{ Kind='Client'; Build=14393; Key='windows_10_1607'; Name='Windows 10 1607'; From=2015 }
    @{ Kind='Client'; Build=15063; Key='windows_10_1703'; Name='Windows 10 1703'; From=2016 }
    @{ Kind='Client'; Build=16299; Key='windows_10_1709'; Name='Windows 10 1709'; From=2017 }
    @{ Kind='Client'; Build=17134; Key='windows_10_1803'; Name='Windows 10 1803'; From=2017 }
    @{ Kind='Client'; Build=17763; Key='windows_10_1809'; Name='Windows 10 1809'; From=2017 }
    @{ Kind='Client'; Build=18362; Key='windows_10_1903'; Name='Windows 10 1903'; From=2018 }
    @{ Kind='Client'; Build=18363; Key='windows_10_1909'; Name='Windows 10 1909'; From=2019 }
    @{ Kind='Client'; Build=19041; Key='windows_10_2004'; Name='Windows 10 2004'; From=2019 }
    @{ Kind='Client'; Build=19042; Key='windows_10_20h2'; Name='Windows 10 20H2'; From=2019 }
    @{ Kind='Client'; Build=19043; Key='windows_10_21h1'; Name='Windows 10 21H1'; From=2020 }
    @{ Kind='Client'; Build=19044; Key='windows_10_21h2'; Name='Windows 10 21H2'; From=2020 }
    @{ Kind='Client'; Build=19045; Key='windows_10_22h2'; Name='Windows 10 22H2'; From=2020 }
    @{ Kind='Client'; Build=22000; Key='windows_11_21h2'; Name='Windows 11 21H2'; From=2020 }
    @{ Kind='Client'; Build=22621; Key='windows_11_22h2'; Name='Windows 11 22H2'; From=2020 }
    @{ Kind='Client'; Build=22631; Key='windows_11_23h2'; Name='Windows 11 23H2'; From=2022 }
    @{ Kind='Client'; Build=26100; Key='windows_11_24h2'; Name='Windows 11 24H2'; From=2023 }
    @{ Kind='Client'; Build=26200; Key='windows_11_25h2'; Name='Windows 11 25H2'; From=2024 }
    @{ Kind='Client'; Build=26300; Key='windows_11_26h2'; Name='Windows 11 26H2'; From=2025 }
    @{ Kind='Client'; Build=28000; Key='windows_11_26h1'; Name='Windows 11 26H1'; From=2025 }
    @{ Kind='Server'; Build=14393; Key='windows_server_2016'; Name='Windows Server 2016'; From=2015 }
    @{ Kind='Server'; Build=17763; Key='windows_server_2019'; Name='Windows Server 2019'; From=2017 }
    @{ Kind='Server'; Build=20348; Key='windows_server_2022'; Name='Windows Server 2022'; From=2020 }
    @{ Kind='Server'; Build=25398; Key='windows_server_2022_23h2'; Name='Windows Server 2022 23H2'; From=2022 }
    @{ Kind='Server'; Build=26100; Key='windows_server_2025'; Name='Windows Server 2025'; From=2023 }
    @{ Kind='Server'; Build=17134; Key='windows_server_1803'; Name='Windows Server 1803'; From=2017 }
    @{ Kind='Server'; Build=18362; Key='windows_server_1903'; Name='Windows Server 1903'; From=2018 }
    @{ Kind='Server'; Build=18363; Key='windows_server_1909'; Name='Windows Server 1909'; From=2019 }
    @{ Kind='Server'; Build=19041; Key='windows_server_2004'; Name='Windows Server 2004'; From=2019 }
    @{ Kind='Server'; Build=19042; Key='windows_server_20h2'; Name='Windows Server 20H2'; From=2020 }
    # Nicht mehr unterstützt (kein belastbarer Build-Abgleich)
    @{ Kind='Client'; Build=7601; Key='windows_7';             Name='Windows 7';             From=2000; Eol=$true }
    @{ Kind='Client'; Build=9600; Key='windows_8.1';           Name='Windows 8.1';           From=2000; Eol=$true }
    @{ Kind='Server'; Build=7601; Key='windows_server_2008';   Name='Windows Server 2008 R2'; From=2000; Eol=$true }
    @{ Kind='Server'; Build=9200; Key='windows_server_2012';   Name='Windows Server 2012';   From=2000; Eol=$true }
    @{ Kind='Server'; Build=9600; Key='windows_server_2012';   Name='Windows Server 2012 R2'; From=2000; Eol=$true }
)

# Schwester-Releases: per Enablement-Package auf demselben Wartungszweig (gleiche Binärdateien, gleiche Revision/UBR je
# Patchday, z. B. 10.0.26100.9711 / 10.0.26200.9711 / 10.0.26300.9711). Die NVD trägt neuere Releases nicht bei jeder CVE nach;
# fehlt das eigene Release, werden die Build-Grenzen eines Schwester-Release übernommen (Convert-OsSiblingCpe).
# Windows Server 2025 (ebenfalls Build 26100) hat eigene Revisionen und gehört bewusst NICHT dazu.
$script:OsSiblings = @(
    @{ windows_10_2004 = 19041; windows_10_20h2 = 19042; windows_10_21h1 = 19043; windows_10_21h2 = 19044; windows_10_22h2 = 19045 }
    @{ windows_11_22h2 = 22621; windows_11_23h2 = 22631 }
    @{ windows_11_24h2 = 26100; windows_11_25h2 = 26200; windows_11_26h2 = 26300 }
)

# Build/Typ -> Windows-Release (oder $null, wenn unbekannt). Neuere Windows-11-Releases ohne Tabelleneintrag
# werden über die Anzeigeversion ("26H1") zugeordnet.
function Get-OsRelease([int]$Build, [string]$InstallationType, [string]$DisplayVersion) {
    $kind = if ($InstallationType -match 'Server') { 'Server' } else { 'Client' }
    $r = $script:OsReleases | Where-Object { $_.Build -eq $Build -and $_.Kind -eq $kind } | Select-Object -First 1
    if ($r) { return [PSCustomObject]@{ Key=$r.Key; Name=$r.Name; Kind=$kind; From=[int]$r.From; Eol=[bool]$r.Eol; Known=$true } }
    if ($kind -eq 'Client' -and $Build -ge 22000 -and $DisplayVersion -match '^(\d{2})H[12]$') {
        return [PSCustomObject]@{ Key=('windows_11_' + $DisplayVersion.ToLowerInvariant()); Name=("Windows 11 $DisplayVersion"); Kind=$kind; From=(2000 + [int]$Matches[1] - 1); Eol=$false; Known=$false }
    }
    return $null
}

# Pseudo-Inventareintrag "Windows" für den Build-Abgleich. Version = vollständiger Build (10.0.<Build>.<UBR>).
function New-OsMatchItem($Release, [string]$FullBuild, [string]$Edition) {
    $nm = if ($Edition) { "$($Release.Name) ($Edition)" } else { $Release.Name }
    [PSCustomObject]@{
        Name=$nm; Version=$FullBuild; Source='Betriebssystem'; Tokens=@(Get-Tokens $nm); MatchTokens=@(); VendorTokens=@(); MfrTokens=@()
        Hits=(New-Object System.Collections.Generic.List[object])
        IsOs=$true; OsKey=$Release.Key; OsFrom=[int]$Release.From; OsOld=0
    }
}

# KEV-Einträge zu Windows als Treffer an den Betriebssystem-Eintrag hängen. Einträge, die älter sind als das Release
# (Jahr der CVE < From), werden nicht einzeln gegen die NVD geprüft (OsOld), außer sie stehen auf der Ausnahmeliste.
function Add-OsHits($Item, $KevIndex, [bool]$AllYears = $false) {
    foreach ($ke in $KevIndex) {
        if (-not $ke.IsOs) { continue }
        if (-not $AllYears -and $ke.Year -lt $Item.OsFrom -and ($script:OsAlwaysCheck -notcontains $ke.CVE)) { $Item.OsOld++; continue }
        $Item.Hits.Add([PSCustomObject]@{
            CVE=$ke.CVE; Vendor=$ke.Vendor; Product=$ke.Product; Name=$ke.Name
            Added=$ke.Added; Due=$ke.Due; Ransom=$ke.Ransom; Desc=$ke.Desc
            Action=$ke.Action; Confidence='Hoch'; Basis='Betriebssystem (Build)'
        })
    }
}

# CPE-Einträge der Schwester-Releases von $OsKey auf den eigenen Build umschreiben (10.0.26200.9445 -> 10.0.26300.9445).
# Nur Grenzen, deren Build zu einem Schwester-Release gehört, werden umgeschrieben; From = ursprüngliches CPE-Produkt.
function Convert-OsSiblingCpe([string]$OsKey, $Os) {
    $grp = $script:OsSiblings | Where-Object { $_.ContainsKey($OsKey) } | Select-Object -First 1
    if (-not $grp) { return }
    $own = [string]$grp[$OsKey]
    $builds = @($grp.Values | ForEach-Object { [string]$_ })
    foreach ($c in @($Os | Where-Object { $_.Product -ne $OsKey -and $grp.ContainsKey([string]$_.Product) })) {
        $n = [PSCustomObject]@{ Product = $OsKey; Exact = $c.Exact; VSI = $c.VSI; VSE = $c.VSE; VEI = $c.VEI; VEE = $c.VEE; From = [string]$c.Product }
        foreach ($k in 'Exact', 'VSI', 'VSE', 'VEI', 'VEE') {
            $b = [string]$n.$k
            if ($b -match '^(\d+\.\d+)\.(\d+)(\..*)?$' -and $builds -contains $Matches[2]) { $n.$k = "$($Matches[1]).$own$($Matches[3])" }
        }
        $n
    }
}

# Verdikt für eine Windows-CVE anhand der NVD-CPE-Liste ($Cfg: Product/Exact/VSI/VSE/VEI/VEE wie Get-NvdConfig).
# Class: Affected | Patched | NotListed | Unbounded | NoCpe | NoData
#   NotListed = die NVD führt weder dein Windows-Release noch ein Schwester-Release für diese CVE auf (betrifft andere Releases)
#   Unbounded = dein Release steht ohne Build-Grenze in der NVD -> nicht entscheidbar
# Fehlt nur das eigene Release, wird aus den Schwester-Releases abgeleitet (Begründung nennt das).
function Test-OsCpeVerdict([string]$Build, [string]$OsKey, $Cfg, [bool]$Answered) {
    $r = [PSCustomObject]@{ Class='NoData'; Verdict='Unklar'; Reason=''; Ranges=@(); Matched=@(); Fixed=@() }
    if (-not $Answered) { $r.Reason = L 'Die NVD hat für diese CVE nicht geantwortet (später erneut versuchen).' 'The NVD did not answer for this CVE (try again later).'; return $r }
    $os = @($Cfg | Where-Object { $_.Product -like 'windows*' })
    if ($os.Count -eq 0) {
        $r.Class = 'NoCpe'; $r.Reason = L 'Die NVD nennt für diese CVE keine Windows-Produkte mit Build-Angaben (ggf. noch nicht analysiert).' 'The NVD lists no Windows products with build information for this CVE (possibly not analyzed yet).'; return $r
    }
    $mine = @($os | Where-Object { $_.Product -eq $OsKey })
    $derived = ''
    if ($mine.Count -eq 0) {
        # "Nicht gelistet" ist bei neueren Releases oft nur eine Lücke in der NVD: Treffer fielen sonst still aus dem Bericht.
        $mine = @(Convert-OsSiblingCpe $OsKey $os)
        $derived = (@($mine | ForEach-Object { $_.From } | Select-Object -Unique) -join ', ')
    }
    if ($mine.Count -eq 0) {
        $r.Class = 'NotListed'; $r.Verdict = 'Vermutlich gepatcht'
        $r.Reason = L "Die NVD führt dein Windows-Release ($OsKey) für diese CVE nicht als betroffen auf." "The NVD does not list your Windows release ($OsKey) as affected by this CVE."; return $r
    }
    $rng = New-Object System.Collections.Generic.List[string]; $hit = New-Object System.Collections.Generic.List[string]
    $fixHit = New-Object System.Collections.Generic.List[string]; $fixAll = New-Object System.Collections.Generic.List[string]
    $inRange = $false; $unbounded = $false
    foreach ($c in $mine) {
        $t = Format-CpeRange $c
        if (-not $rng.Contains($t)) { $rng.Add($t) }
        $fx = if ($c.VEE) { "ab $($c.VEE)" } elseif ($c.VEI) { "neuer als $($c.VEI)" } else { '' }
        if ($fx -and -not $fixAll.Contains($fx)) { $fixAll.Add($fx) }
        if (-not ($c.VSI -or $c.VSE -or $c.VEI -or $c.VEE)) { $unbounded = $true; continue }     # ohne Build-Grenze: nicht entscheidbar
        $in = Test-InVulnRange $Build $c
        if ($null -eq $in) { $unbounded = $true; continue }
        if ($in) { $inRange = $true; if (-not $hit.Contains($t)) { $hit.Add($t) }; if ($fx -and -not $fixHit.Contains($fx)) { $fixHit.Add($fx) } }
    }
    $r.Ranges = @($rng); $r.Matched = @($hit)
    $r.Fixed  = @($(if ($fixHit.Count -gt 0) { $fixHit } else { $fixAll }) | Select-Object -First 3)
    if ($inRange)       { $r.Class = 'Affected';  $r.Verdict = 'Betroffen' }
    elseif ($unbounded) { $r.Class = 'Unbounded'; $r.Verdict = 'Unklar'; $r.Reason = L 'Für dein Windows-Release nennt die NVD bei dieser CVE keine Build-Grenze (häufig bei älteren Einträgen); ob dein Build den Fix enthält, lässt sich so nicht sagen.' 'For your Windows release the NVD gives no build boundary for this CVE (common for older entries); whether your build contains the fix cannot be determined this way.' }
    else                { $r.Class = 'Patched';   $r.Verdict = 'Vermutlich gepatcht'; $r.Reason = L 'Dein Build liegt oberhalb aller von der NVD genannten verwundbaren Build-Bereiche.' 'Your build is above all vulnerable build ranges listed by the NVD.' }
    if ($derived) {
        $dDe = "Abgeleitet: Die NVD führt dein Windows-Release ($OsKey) für diese CVE nicht, wohl aber $derived aus demselben Wartungszweig (gleiche Revision je Patchday); deren Build-Grenzen wurden auf deinen Build übertragen."
        $dEn = "Derived: The NVD does not list your Windows release ($OsKey) for this CVE, but lists $derived from the same servicing branch (same revision per Patch Tuesday); their build boundaries were applied to your build."
        $r.Reason = if ($r.Reason) { L "$dDe $($r.Reason.de)" "$dEn $($r.Reason.en)" } else { L $dDe $dEn }
    }
    return $r
}

# ---------------------------------------------------------------------------
# CHROMIUM-BASIERTE PROGRAMME (Microsoft Edge): Die NVD führt Chromium-Fehler fast immer für Chrome ("google:chrome"), für Edge
# nur teilweise ("microsoft:edge_chromium"). Fehlt Edge in der NVD-Liste, wird aus der Hauptversion geschlossen:
# Edge <N>.x basiert auf Chromium <N>.
# ---------------------------------------------------------------------------
# Hat der CPE-Eintrag eine Versionsgrenze im Chromium-Edge-Schema (Hauptversion >= 79)? Ohne Grenze oder mit alten
# EdgeHTML-Versionen (44.x) ist er für Edge-Chromium nicht verwertbar.
function Test-ChromiumEraCpe($cpe) {
    foreach ($b in @($cpe.VEE, $cpe.VEI, $cpe.VSI, $cpe.VSE)) {
        if ($b) { $maj = @(ConvertTo-VerArray ([string]$b))[0]; return ($maj -ge 79) }
    }
    return $false
}
function Get-VerMajor([string]$v) { $a = @(ConvertTo-VerArray $v); if ($a.Count -gt 0) { return [long]$a[0] } else { return -1 } }

# Aus dem Chrome-Fix (versionEndExcluding) auf Edge schließen. $null = nicht möglich (kein Chrome-Fix in der NVD-Liste).
function Test-ChromiumDerivedVerdict([string]$Installed, $Cfg) {
    $chr = @($Cfg | Where-Object { $_.Product -eq 'chrome' -and $_.VEE })
    if ($chr.Count -eq 0) { return $null }
    $fix = ($chr | Sort-Object { Get-VerMajor ([string]$_.VEE) } -Descending | Select-Object -First 1).VEE     # Fix im aktuellen Ast
    $fixMajor = Get-VerMajor ([string]$fix); $inst = Get-VerMajor $Installed
    if ($inst -lt 0 -or $fixMajor -lt 0) { return $null }
    $r = [PSCustomObject]@{ Class='Derived'; Verdict='Unklar'; Reason=''; Ranges=@("Chromium < $fix"); Matched=@(); Fixed=@("Chromium ab $fix") }
    if ($inst -gt $fixMajor) {
        $r.Verdict = 'Vermutlich gepatcht'
        $r.Reason = L "Abgeleitet: Edge $Installed basiert auf Chromium $inst; der Chromium-Fix steckt ab Version $fix (Chromium $fixMajor). Die NVD nennt Edge für diese CVE nicht." "Derived: Edge $Installed is based on Chromium $inst; the Chromium fix is included from version $fix (Chromium $fixMajor). The NVD does not list Edge for this CVE."
    } elseif ($inst -lt $fixMajor) {
        $r.Verdict = 'Betroffen'; $r.Matched = @("Chromium < $fix")
        $r.Reason = L "Abgeleitet: Edge $Installed basiert auf Chromium $inst, der Fix steckt erst ab Chromium $fix. Die NVD nennt Edge für diese CVE nicht." "Derived: Edge $Installed is based on Chromium $inst, the fix is only included from Chromium $fix. The NVD does not list Edge for this CVE."
    } else {
        $r.Reason = L "Edge und der Chromium-Fix ($fix) haben dieselbe Hauptversion ($fixMajor); die NVD nennt Edge für diese CVE nicht, der genaue Fix-Build für Edge ist daher unbekannt." "Edge and the Chromium fix ($fix) have the same major version ($fixMajor); the NVD does not list Edge for this CVE, so the exact fix build for Edge is unknown."
    }
    return $r
}

# Verdikt für ein Chromium-basiertes Programm: 1) CPE-Einträge des Programms selbst (z. B. edge_chromium) mit Versionsgrenze, 2) sonst abgeleitet aus dem Chrome-Fix.
function Test-ChromiumBaseVerdict([string]$Installed, [string[]]$CpeProducts, $Cfg, [string]$CveId = '') {
    $own = @($Cfg | Where-Object { $CpeProducts -contains $_.Product -and (Test-ChromiumEraCpe $_) })
    if ($own.Count -gt 0) {
        $rng = New-Object System.Collections.Generic.List[string]; $hit = New-Object System.Collections.Generic.List[string]; $fixH = New-Object System.Collections.Generic.List[string]; $fixA = New-Object System.Collections.Generic.List[string]
        $in = $false
        foreach ($c in $own) {
            $t = Format-CpeRange $c; if (-not $rng.Contains($t)) { $rng.Add($t) }
            $fx = if ($c.VEE) { "ab $($c.VEE)" } elseif ($c.VEI) { "neuer als $($c.VEI)" } else { '' }
            if ($fx -and -not $fixA.Contains($fx)) { $fixA.Add($fx) }
            if (Test-InVulnRange $Installed $c) { $in = $true; if (-not $hit.Contains($t)) { $hit.Add($t) }; if ($fx -and -not $fixH.Contains($fx)) { $fixH.Add($fx) } }
        }
        $r = [PSCustomObject]@{ Class='Own'; Verdict='Vermutlich gepatcht'; Reason=(L 'Die installierte Version liegt außerhalb aller von der NVD genannten verwundbaren Bereiche.' 'The installed version is outside all vulnerable ranges listed by the NVD.'); Ranges=@($rng); Matched=@($hit); Fixed=@($(if ($fixH.Count) { $fixH } else { $fixA }) | Select-Object -First 3) }
        if ($in) { $r.Verdict = 'Betroffen'; $r.Reason = '' }
        return $r
    }
    $d = Test-ChromiumDerivedVerdict $Installed $Cfg
    if ($d) { return $d }
    # Nur Einträge des früheren Edge (EdgeHTML, bis 2020; die NVD führt sie ohne Versionsgrenze): betrifft das heutige Chromium-Edge nicht
    $yr = if ($CveId -match '^CVE-(\d{4})-') { [int]$Matches[1] } else { 9999 }
    if ($yr -le 2020 -and @($Cfg | Where-Object { $CpeProducts -contains $_.Product }).Count -gt 0) {
        return [PSCustomObject]@{ Class='Legacy'; Verdict='Vermutlich gepatcht'; Reason=(L 'Betrifft nur das frühere Edge (EdgeHTML, bis 2020); das heutige Edge basiert auf Chromium.' 'Only affects the former Edge (EdgeHTML, until 2020); today''s Edge is based on Chromium.'); Ranges=@('Edge Legacy (EdgeHTML)'); Matched=@(); Fixed=@() }
    }
    return [PSCustomObject]@{ Class='NoInfo'; Verdict='Unklar'; Reason=(L 'Die NVD nennt für diese CVE weder dieses Programm noch eine Chromium-Fixversion; keine Aussage möglich.' 'The NVD lists neither this program nor a Chromium fix version for this CVE; no statement possible.'); Ranges=@(); Matched=@(); Fixed=@() }
}

# 2c) Click-to-Run-Office (Project, Visio, Office-Apps ...): Builds wie 16.0.14931.20274 sind NICHT mit den Versionsgrenzen der NVD
#     vergleichbar (die stammen von MSI-Installationen, z. B. 16.0.5461.1001; 14931 > 5461 heißt NICHT "gepatcht").
#     Solche Programme bekommen nie ein Versions-Verdikt, sondern "Unklar" mit Begründung.
$script:C2RNameRegex = '^microsoft (project|visio|office|word|excel|outlook|powerpoint|publisher|access|onenote|365)\b'

# 4) Bekannte Abdeckungslücken: Programme, zu denen der KEV-Abgleich nichts oder nur eingeschränkt aussagen kann.
#    Werden im Report unter "Aussagekraft dieses Scans" ausgewiesen (statt stillschweigend "keine Treffer").
$script:CoverageGapRules = @(
    @{ Name='^microsoft 365\b|^microsoft office 365\b'; Label=(L 'Microsoft 365 Apps (Click-to-Run)' 'Microsoft 365 Apps (Click-to-Run)')
       Note=(L 'KEV-Einträge zu Microsoft Office werden Click-to-Run-Installationen nicht zugeordnet (der Versionsvergleich per CPE ist dort nicht belastbar). Update-Kanal und Build separat prüfen, z. B. im Microsoft 365 Apps Admin Center.' 'KEV entries for Microsoft Office are not matched to Click-to-Run installations (the CPE version comparison is not reliable there). Check update channel and build separately, e.g. in the Microsoft 365 Apps admin center.') }
    @{ Name='\b(brave|vivaldi|opera)\b'; Label=(L 'Chromium-Browser außer Chrome und Edge' 'Chromium browsers other than Chrome and Edge')
       Note=(L 'KEV-Einträge zu Chromium werden Google Chrome und Microsoft Edge zugeordnet; andere Chromium-Browser haben eigene Versionsnummern ohne verlässliche Zuordnung zur Chromium-Version. Browser aktuell halten.' 'KEV entries for Chromium are matched to Google Chrome and Microsoft Edge; other Chromium browsers have their own version numbers without a reliable mapping to the Chromium version. Keep the browser up to date.') }
)
function Get-CoverageGaps($names) {
    foreach ($r in $script:CoverageGapRules) {
        $hit = @($names | Where-Object { ([string]$_).ToLowerInvariant() -match $r.Name })
        if ($hit.Count -gt 0) { [PSCustomObject]@{ Label = $r.Label; Note = $r.Note; Items = @($hit | Group-Object { ([string]$_).ToLowerInvariant() } | ForEach-Object { $_.Group[0] } | Select-Object -First 3) } }
    }
}
# ---------------------------------------------------------------------------
# NVD-WARTESCHLANGE: Treffer aus dem Cache sind kostenlos, nur echte Abfragen zählen gegen das Limit; der Rest wird zurückgestellt
# (Skipped) und im Report als "Scan unvollständig" ausgewiesen.
# ---------------------------------------------------------------------------
function Get-NvdQueue([string[]]$Candidates, [scriptblock]$IsCached, [int]$Budget) {
    $queue = New-Object System.Collections.Generic.List[string]; $skipped = New-Object System.Collections.Generic.List[string]
    $left = $Budget
    foreach ($c in $Candidates) {
        if (& $IsCached $c) { $queue.Add($c) }
        elseif ($left -gt 0) { $queue.Add($c); $left-- }
        else { $skipped.Add($c) }
    }
    [PSCustomObject]@{ Queue = @($queue); Skipped = @($skipped) }
}

# ---------------------------------------------------------------------------
# LAUSCHENDE PORTS: Einordnung für den Report.
#   ms      = Windows-Standard (grün): bekannter Windows-Port UND erwarteter Prozess
#   remote  = Fernzugriff/Verwaltung (gelb): nur wenn gewollt
#   risk    = veraltet/unverschlüsselt (rot)
#   known   = bekannter Dienst (grau-blau): prüfen, ob gewollt
#   unusual = Standard-Port, aber ungewöhnlicher Prozess (gelb): prüfen!
#   unknown = kein bekannter Port / Prozess unbekannt (grau)
# ---------------------------------------------------------------------------
$script:PortKinds = @{
    ms = (L 'Windows-Standard' 'Windows default'); remote = (L 'Fernzugriff' 'Remote access'); risk = (L 'Veraltet / unverschlüsselt' 'Outdated / unencrypted')
    known = (L 'Bekannter Dienst' 'Known service'); unusual = (L 'Ungewöhnlich' 'Unusual'); unknown = (L 'Unbekannt' 'Unknown')
}
$script:RpcDynProcs = '^(lsass|wininit|services|svchost|spoolsv|winlogon|System)$'
# Je Port: Name/Hint (deutsch) und NameEn/HintEn (englisch)
$script:PortTable = @(
    @{ P=135;  Kind='ms'; Proc='^svchost$'; Name='RPC-Endpunktzuordnung'; NameEn='RPC endpoint mapper'
       Hint='Windows-Standard (Remote Procedure Call). Viele Windows-Funktionen nutzen ihn. Nur im internen Netz sinnvoll: aus dem Internet nie erreichbar machen (Firewall).'
       HintEn='Windows default (Remote Procedure Call). Many Windows functions use it. Only useful in the internal network: never make it reachable from the internet (firewall).' }
    @{ P=139;  Kind='ms'; Proc='^System$'; Name='NetBIOS-Sitzungsdienst'; NameEn='NetBIOS session service'
       Hint='Altes Windows-Netzwerkprotokoll für Datei- und Druckerfreigaben. Heute meist nur noch für sehr alte Geräte nötig; in reinen SMB-Umgebungen kann es abgeschaltet werden.'
       HintEn='Old Windows network protocol for file and printer sharing. Today usually only needed for very old devices; in pure SMB environments it can be switched off.' }
    @{ P=445;  Kind='ms'; Proc='^System$'; Name='SMB (Datei- und Druckerfreigabe)'; NameEn='SMB (file and printer sharing)'
       Hint='Windows-Standard für Netzwerkfreigaben. Im Firmennetz üblich, aber ein häufiges Angriffsziel (z. B. Ausbreitung von Ransomware). Per Firewall nur im internen Netz erlauben.'
       HintEn='Windows default for network shares. Common in company networks, but a frequent attack target (e.g. spreading of ransomware). Allow only in the internal network via firewall.' }
    @{ P=2179; Kind='ms'; Proc='^vmms$'; Name='Hyper-V-Verbindung'; NameEn='Hyper-V connection'
       Hint='Nur mit Hyper-V relevant (Verbindung zu virtuellen Maschinen).'
       HintEn='Only relevant with Hyper-V (connection to virtual machines).' }
    @{ P=2869; Kind='ms'; Proc='^System$'; Name='UPnP-/SSDP-Geräteerkennung'; NameEn='UPnP/SSDP device discovery'
       Hint='Windows-Standard zur Erkennung von Netzwerkgeräten (z. B. Medienserver). Im Heimnetz üblich.'
       HintEn='Windows default for discovering network devices (e.g. media servers). Common in home networks.' }
    @{ P=5040; Kind='ms'; Proc='^svchost$'; Name='Verbundene Geräte (CDPSvc)'; NameEn='Connected devices (CDPSvc)'
       Hint='Windows-Standard (Connected Devices Platform, z. B. Nahe Freigabe). Üblich und harmlos.'
       HintEn='Windows default (Connected Devices Platform, e.g. Nearby Sharing). Common and harmless.' }
    @{ P=5357; Kind='ms'; Proc='^System$'; Name='WSDAPI-Geräteerkennung (HTTP)'; NameEn='WSDAPI device discovery (HTTP)'
       Hint='Windows-Standard: Erkennung von Netzwerkgeräten wie Druckern. Im Heimnetz üblich.'
       HintEn='Windows default: discovery of network devices such as printers. Common in home networks.' }
    @{ P=5358; Kind='ms'; Proc='^System$'; Name='WSDAPI-Geräteerkennung (HTTPS)'; NameEn='WSDAPI device discovery (HTTPS)'
       Hint='Windows-Standard: Erkennung von Netzwerkgeräten wie Druckern. Im Heimnetz üblich.'
       HintEn='Windows default: discovery of network devices such as printers. Common in home networks.' }
    @{ P=7680; Kind='ms'; Proc='^svchost$'; Name='Übermittlungsoptimierung'; NameEn='Delivery Optimization'
       Hint='Windows-Standard (Delivery Optimization): Windows kann Updates auch von anderen PCs im Netz laden. In den Windows-Update-Einstellungen abschaltbar.'
       HintEn='Windows default (Delivery Optimization): Windows can also download updates from other PCs on the network. Can be switched off in the Windows Update settings.' }
    @{ P=3389; Kind='remote'; Proc='^svchost$'; Name='Remotedesktop (RDP)'; NameEn='Remote Desktop (RDP)'
       Hint='Erlaubt Fernzugriff auf diesen Rechner. Nur aktiv lassen, wenn gewollt: ein häufiges Einfallstor für Angriffe. Nie direkt aus dem Internet erreichbar machen, nur über VPN und mit Netzwerkauthentifizierung (NLA).'
       HintEn='Allows remote access to this computer. Only keep it enabled if intended: a common entry point for attacks. Never make it directly reachable from the internet, only via VPN and with Network Level Authentication (NLA).' }
    @{ P=5985; Kind='remote'; Proc='^System$'; Name='WinRM / PowerShell-Remoting'; NameEn='WinRM / PowerShell remoting'
       Hint='Windows-Fernverwaltung (PowerShell Remoting). Nur auf verwalteten Geräten gewollt, sonst deaktivieren.'
       HintEn='Windows remote management (PowerShell remoting). Only intended on managed devices, otherwise disable.' }
    @{ P=5986; Kind='remote'; Proc='^System$'; Name='WinRM (HTTPS)'; NameEn='WinRM (HTTPS)'
       Hint='Windows-Fernverwaltung über HTTPS. Nur auf verwalteten Geräten gewollt, sonst deaktivieren.'
       HintEn='Windows remote management over HTTPS. Only intended on managed devices, otherwise disable.' }
    @{ P=22;   Kind='remote'; Name='SSH'; NameEn='SSH'
       Hint='Verschlüsselter Fernzugriff per Kommandozeile. Nur aktiv lassen, wenn gewollt; Schlüssel statt Kennwörter nutzen.'
       HintEn='Encrypted remote command-line access. Only keep it enabled if intended; use keys instead of passwords.' }
    @{ P=5900; Kind='remote'; Name='VNC (Fernsteuerung)'; NameEn='VNC (remote control)'
       Hint='Fernsteuerung des Bildschirms, oft ohne starke Verschlüsselung. Nur über VPN und nur wenn gewollt.'
       HintEn='Remote control of the screen, often without strong encryption. Only via VPN and only if intended.' }
    @{ P=5938; Kind='remote'; Name='TeamViewer'; NameEn='TeamViewer'
       Hint='Fernwartungssoftware. Nur gewollt, wenn TeamViewer bewusst genutzt wird.'
       HintEn='Remote support software. Only intended if TeamViewer is used deliberately.' }
    @{ P=7070; Kind='remote'; Name='AnyDesk'; NameEn='AnyDesk'
       Hint='Fernwartungssoftware. Nur gewollt, wenn AnyDesk bewusst genutzt wird.'
       HintEn='Remote support software. Only intended if AnyDesk is used deliberately.' }
    @{ P=23;   Kind='risk'; Name='Telnet'; NameEn='Telnet'
       Hint='Unverschlüsselter Fernzugriff: Kennwörter laufen im Klartext durchs Netz. Abschalten und durch SSH ersetzen.'
       HintEn='Unencrypted remote access: passwords travel through the network in plain text. Switch off and replace with SSH.' }
    @{ P=21;   Kind='risk'; Name='FTP'; NameEn='FTP'
       Hint='Unverschlüsselte Dateiübertragung (Kennwörter im Klartext). Durch SFTP oder FTPS ersetzen.'
       HintEn='Unencrypted file transfer (passwords in plain text). Replace with SFTP or FTPS.' }
    @{ P=80;   Kind='known'; Name='Webserver (HTTP)'; NameEn='Web server (HTTP)'
       Hint='Ein Programm stellt eine Webseite oder Weboberfläche bereit (unverschlüsselt). Prüfen, ob gewollt.'
       HintEn='A program provides a web page or web interface (unencrypted). Check whether this is intended.' }
    @{ P=443;  Kind='known'; Name='Webserver (HTTPS)'; NameEn='Web server (HTTPS)'
       Hint='Ein Programm stellt eine verschlüsselte Webseite oder Weboberfläche bereit. Prüfen, ob gewollt.'
       HintEn='A program provides an encrypted web page or web interface. Check whether this is intended.' }
    @{ P=8080; Kind='known'; Name='Alternativer Webserver'; NameEn='Alternative web server'
       Hint='Häufig Entwicklungsserver, Proxy oder Verwaltungsoberfläche. Prüfen, ob gewollt.'
       HintEn='Often a development server, proxy or management interface. Check whether this is intended.' }
    @{ P=1433; Kind='known'; Name='Microsoft SQL Server'; NameEn='Microsoft SQL Server'
       Hint='Datenbankserver. Nur im internen Netz erreichbar machen und nur, wenn gewollt.'
       HintEn='Database server. Only make it reachable in the internal network and only if intended.' }
    @{ P=3306; Kind='known'; Name='MySQL / MariaDB'; NameEn='MySQL / MariaDB'
       Hint='Datenbankserver. Nur im internen Netz erreichbar machen und nur, wenn gewollt.'
       HintEn='Database server. Only make it reachable in the internal network and only if intended.' }
    @{ P=5432; Kind='known'; Name='PostgreSQL'; NameEn='PostgreSQL'
       Hint='Datenbankserver. Nur im internen Netz erreichbar machen und nur, wenn gewollt.'
       HintEn='Database server. Only make it reachable in the internal network and only if intended.' }
    @{ P=9100; Kind='known'; Name='Drucker (RAW/JetDirect)'; NameEn='Printer (RAW/JetDirect)'
       Hint='Direktdruck-Port eines Druckers oder Druckdienstes. Im Büronetz üblich.'
       HintEn='Direct printing port of a printer or print service. Common in office networks.' }
)

# Einordnung eines lauschenden Ports ($Processes = Namen der Prozesse, die ihn geöffnet haben). Name/Hint sind zweisprachig (L).
function Get-PortInfo([int]$Port, [string[]]$Processes) {
    $procs = @($Processes | Where-Object { $_ })
    $pj = $procs -join ', '
    $e = $script:PortTable | Where-Object { $_.P -eq $Port } | Select-Object -First 1
    if ($e) {
        $name = L $e.Name $e.NameEn; $kind = $e.Kind; $hint = L $e.Hint $e.HintEn
        if ($e.Proc -and ($kind -eq 'ms' -or $kind -eq 'remote')) {
            if ($procs.Count -eq 0) {
                $hint = L "$($e.Hint) (Der Prozess war nicht ermittelbar, z. B. ohne Administratorrechte; deshalb nicht als Windows-Standard bestätigt.)" "$($e.HintEn) (The process could not be determined, e.g. without administrator rights; therefore not confirmed as a Windows default.)"
                if ($kind -eq 'ms') { $kind = 'known' }
            } elseif (@($procs | Where-Object { $_ -notmatch $e.Proc }).Count -gt 0) {
                $kind = 'unusual'
                $hint = L "Dieser Port gehört normalerweise zu $($e.Name), wird hier aber von `"$pj`" geöffnet. Prüfen, ob das gewollt ist: Schadsoftware tarnt sich teils auf Standardports." "This port normally belongs to $($e.NameEn), but is opened here by `"$pj`". Check whether this is intended: malware sometimes disguises itself on standard ports."
            }
        }
    } elseif ($Port -ge 49152) {
        if ($procs.Count -gt 0 -and @($procs | Where-Object { $_ -notmatch $script:RpcDynProcs }).Count -eq 0) {
            $name = L 'Dynamischer RPC-Port (Windows)' 'Dynamic RPC port (Windows)'; $kind = 'ms'
            $hint = L 'Windows nutzt zufällige Ports ab 49152 für interne Dienste (Anmeldung, Dienste, Druckwarteschlange). Normal.' 'Windows uses random ports from 49152 for internal services (logon, services, print spooler). Normal.'
        } elseif ($procs.Count -eq 0) {
            $name = L 'Dynamischer Port' 'Dynamic port'; $kind = 'unknown'
            $hint = L 'Hoher, dynamisch vergebener Port. Der Prozess war nicht ermittelbar (z. B. ohne Administratorrechte).' 'High, dynamically assigned port. The process could not be determined (e.g. without administrator rights).'
        } else {
            $name = L 'Dynamischer Port' 'Dynamic port'; $kind = 'unknown'
            $hint = L "Hoher Port, geöffnet von `"$pj`". Windows nutzt diesen Bereich selbst, Anwendungen aber auch: prüfen, ob die Software bekannt und gewollt ist." "High port, opened by `"$pj`". Windows uses this range itself, but so do applications: check whether the software is known and intended."
        }
    } else {
        $name = L 'Unbekannter Dienst' 'Unknown service'; $kind = 'unknown'
        $hint = if ($procs.Count -gt 0) { L "Kein Windows-Standardport, geöffnet von `"$pj`". Gehört vermutlich zu einer installierten Anwendung: prüfen, ob die Software bekannt und gewollt ist." "Not a Windows default port, opened by `"$pj`". Probably belongs to an installed application: check whether the software is known and intended." } else { L 'Kein Windows-Standardport; der Prozess war nicht ermittelbar. Prüfen, ob der Dienst gewollt ist.' 'Not a Windows default port; the process could not be determined. Check whether the service is intended.' }
    }
    $rank = @{ risk = 0; unusual = 1; remote = 2; unknown = 3; known = 4; ms = 5 }[$kind]
    [PSCustomObject]@{ Port = $Port; Name = $name; Kind = $kind; Label = $script:PortKinds[$kind]; Hint = $hint; Rank = $rank }
}
# <<< MATCHER-KERN-ENDE

# ---------------------------------------------------------------------------
# OS-LEBENSZYKLUS: Wird das installierte Windows noch mit Sicherheitsupdates versorgt?
# Daten: Microsoft-Lifecycle (Stand 11/2026). Neue Releases hier ergänzen; unbekannte, NEUERE Windows-11-Releases
# gelten als unterstützt (Lebenszyklus nicht hinterlegt). Home/Pro und Enterprise/Education haben je Release
# unterschiedliche Enddaten (24 bzw. 36 Monate); LTSC und Server haben eigene Zyklen.
# ---------------------------------------------------------------------------
$script:OsSoonDays = 120      # so viele Tage vor dem Support-Ende: Hinweis "endet bald"
$script:Win11Lifecycle = @{   # Anzeigeversion -> Ende Home/Pro (HP) bzw. Enterprise/Education (EE)
    '21H2' = @{ HP = '2023-10-10'; EE = '2024-10-08' }
    '22H2' = @{ HP = '2024-10-08'; EE = '2025-10-14' }
    '23H2' = @{ HP = '2025-11-11'; EE = '2026-11-10' }
    '24H2' = @{ HP = '2026-10-13'; EE = '2027-10-12' }
    '25H2' = @{ HP = '2027-10-12'; EE = '2028-10-10' }
}
$script:ServerLifecycle = @{  # Build -> Name + Ende des erweiterten Supports
    7601  = @{ N = 'Windows Server 2008 R2';   E = '2020-01-14' }
    9200  = @{ N = 'Windows Server 2012';      E = '2023-10-10' }
    9600  = @{ N = 'Windows Server 2012 R2';   E = '2023-10-10' }
    14393 = @{ N = 'Windows Server 2016';      E = '2027-01-12' }
    17134 = @{ N = 'Windows Server 1803';      E = '2019-11-12' }
    17763 = @{ N = 'Windows Server 2019';      E = '2029-01-09' }
    18362 = @{ N = 'Windows Server 1903';      E = '2020-12-08' }
    18363 = @{ N = 'Windows Server 1909';      E = '2021-05-11' }
    19041 = @{ N = 'Windows Server 2004';      E = '2021-12-14' }
    19042 = @{ N = 'Windows Server 20H2';      E = '2022-08-09' }
    20348 = @{ N = 'Windows Server 2022';      E = '2031-10-14' }
    25398 = @{ N = 'Windows Server 23H2';      E = '2025-10-24' }
    26100 = @{ N = 'Windows Server 2025';      E = '2034-11-14' }
}
$script:LtscLifecycle = @{    # Build -> Name + Ende (Enterprise LTSC/LTSB bzw. IoT Enterprise LTSC)
    10240 = @{ N = 'Windows 10 Enterprise LTSB 2015'; E = '2025-10-14'; IoT = '2025-10-14' }
    14393 = @{ N = 'Windows 10 Enterprise LTSB 2016'; E = '2026-10-13'; IoT = '2026-10-13' }
    17763 = @{ N = 'Windows 10 Enterprise LTSC 2019'; E = '2029-01-09'; IoT = '2029-01-09' }
    19044 = @{ N = 'Windows 10 Enterprise LTSC 2021'; E = '2027-01-12'; IoT = '2032-01-13' }
    26100 = @{ N = 'Windows 11 Enterprise LTSC 2024'; E = '2029-10-09'; IoT = '2034-10-10' }
}
$script:EditionNames = @{ Core = 'Home'; CoreN = 'Home N'; CoreSingleLanguage = 'Home'; Professional = 'Pro'; ProfessionalN = 'Pro N'
    ProfessionalWorkstation = 'Pro for Workstations'; ProfessionalEducation = 'Pro Education'; Enterprise = 'Enterprise'; Education = 'Education' }

# Ergebnis: State = ok | soon | eol | unknown; Text/Title/Detail zweisprachig (L) für Posture und Management-Übersicht
function Get-OsSupportInfo([int]$Build, [string]$InstallationType, [string]$DisplayVersion, [string]$EditionID, [datetime]$Today = (Get-Date)) {
    $r = [PSCustomObject]@{ State = 'unknown'; Text = (L 'n/a' 'n/a'); Name = ''; End = $null; Title = $null; Detail = $null }
    if ($Build -le 0) { return $r }
    $fmt = { param($d) ([datetime]::ParseExact($d, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)) }
    # $eol = @(TitelDE, TitelEN, HinweisDE, HinweisEN)
    $judge = {
        param([string]$name, [string]$endStr, [string[]]$eol)
        $end = & $fmt $endStr; $r.Name = $name; $r.End = $end
        $dDe = $end.ToString('dd.MM.yyyy'); $dEn = $end.ToString('yyyy-MM-dd')
        $days = ($end.Date - $Today.Date).Days
        if ($days -lt 0) {
            $r.State = 'eol'
            $r.Text  = L ('{0} - Support endete am {1}; keine Sicherheitsupdates mehr (Risiko)' -f $name, $dDe) ('{0} - support ended on {1}; no more security updates (risk)' -f $name, $dEn)
            $r.Title = L $eol[0] $eol[1]
            $r.Detail = L ('{0} erhält seit dem {1} keine Sicherheitsupdates mehr. {2}' -f $name, $dDe, $eol[2]) ('{0} has not received security updates since {1}. {2}' -f $name, $dEn, $eol[3])
        } elseif ($days -le $script:OsSoonDays) {
            $r.State = 'soon'
            $r.Text  = L ('{0} - unterstützt bis {1}, endet in {2} Tagen (Hinweis)' -f $name, $dDe, $days) ('{0} - supported until {1}, ends in {2} days (notice)' -f $name, $dEn, $days)
            $r.Title = L 'Upgrade der Windows-Version einplanen' 'Plan an upgrade of the Windows version'
            $r.Detail = L ('Der Support für {0} endet am {1}. {2}' -f $name, $dDe, $eol[2]) ('Support for {0} ends on {1}. {2}' -f $name, $dEn, $eol[3])
        } else {
            $r.State = 'ok'; $r.Text = L ('{0} - unterstützt bis {1}' -f $name, $dDe) ('{0} - supported until {1}' -f $name, $dEn)
        }
    }
    $ed = if ($script:EditionNames.ContainsKey($EditionID)) { $script:EditionNames[$EditionID] } else { $EditionID }

    # Server: eigener Zyklus je Version
    if ($InstallationType -match 'Server') {
        $sv = $script:ServerLifecycle[$Build]
        if ($sv) { & $judge $sv.N $sv.E @('Server-Betriebssystem migrieren oder ESU sicherstellen', 'Migrate the server operating system or ensure ESU',
                    'Auf eine unterstützte Windows-Server-Version migrieren oder erweiterte Sicherheitsupdates (ESU) sicherstellen; ein vorhandener ESU-Vertrag wird vom Scan nicht erkannt.',
                    'Migrate to a supported Windows Server version or ensure Extended Security Updates (ESU); an existing ESU contract is not detected by the scan.') }
        else { $r.Text = L "Windows Server (Build $Build) - Lebenszyklus nicht hinterlegt, bitte prüfen" "Windows Server (build $Build) - lifecycle not on file, please check" }
        return $r
    }
    # LTSC/LTSB (EditionID endet auf "S", z. B. EnterpriseS, IoTEnterpriseS): eigener, langer Zyklus
    if ($EditionID -match '^(IoT)?Enterprise(S|SN)$') {
        $lt = $script:LtscLifecycle[$Build]
        if ($lt) { & $judge $lt.N $(if ($EditionID -like 'IoT*') { $lt.IoT } else { $lt.E }) @('Auf eine unterstützte LTSC-Version wechseln', 'Move to a supported LTSC version',
                    'Auf eine unterstützte LTSC-Version bzw. Windows 11 wechseln.', 'Move to a supported LTSC version or Windows 11.') }
        else { $r.Text = L "Windows LTSC/LTSB (Build $Build) - Lebenszyklus nicht hinterlegt, bitte prüfen" "Windows LTSC/LTSB (build $Build) - lifecycle not on file, please check" }
        return $r
    }
    $isEE = ($EditionID -match '^(Enterprise|Education|IoTEnterprise|ServerRdsh|EnterpriseG)')
    if ($Build -ge 22000) {
        $dv = "$DisplayVersion".ToUpperInvariant()
        $lc = $script:Win11Lifecycle[$dv]
        $nm = ('Windows 11 {0}{1}' -f $dv, $(if ($ed) { " ($ed)" } else { '' }))
        if ($lc) {
            & $judge $nm $(if ($isEE) { $lc.EE } else { $lc.HP }) @('Auf eine unterstützte Windows-11-Version aktualisieren', 'Update to a supported Windows 11 version',
                'Über Windows Update das aktuelle Funktionsupdate installieren (Einstellungen > Windows Update).', 'Install the current feature update via Windows Update (Settings > Windows Update).')
        } elseif ($dv -match '^(\d{2})H([12])$' -and ([int]$Matches[1] * 10 + [int]$Matches[2]) -gt 252) {
            $r.State = 'ok'; $r.Name = $nm; $r.Text = L "$nm - aktuelles Release (Lebenszyklus nicht hinterlegt)" "$nm - current release (lifecycle not on file)"
        } else { $r.Text = L "Windows 11 (Build $Build, $DisplayVersion) - Lebenszyklus nicht hinterlegt, bitte prüfen" "Windows 11 (build $Build, $DisplayVersion) - lifecycle not on file, please check" }
        return $r
    }
    if ($Build -ge 10240) {
        $r.State = 'eol'; $r.Name = 'Windows 10'; $r.End = (& $fmt '2025-10-14')
        $r.Text  = L 'Windows 10 - regulärer Support endete am 14.10.2025; Sicherheitsupdates nur mit ESU (Risiko)' 'Windows 10 - regular support ended on 2025-10-14; security updates only with ESU (risk)'
        $r.Title = L 'Auf Windows 11 wechseln oder erweiterte Sicherheitsupdates (ESU) sicherstellen' 'Move to Windows 11 or ensure Extended Security Updates (ESU)'
        $r.Detail = L 'Windows 10 ist seit dem 14.10.2025 nicht mehr regulär unterstützt; ohne ESU gibt es keine Sicherheitsupdates mehr (ein vorhandener ESU-Vertrag wird vom Scan nicht erkannt).' 'Windows 10 has not been regularly supported since 2025-10-14; without ESU there are no more security updates (an existing ESU contract is not detected by the scan).'
        return $r
    }
    $r.State = 'eol'; $r.Name = "Windows (Build $Build)"
    $r.Text  = L "Ältere Windows-Version (Build $Build), nicht mehr unterstützt (Risiko)" "Older Windows version (build $Build), no longer supported (risk)"
    $r.Title = L 'Nicht mehr unterstütztes Windows ersetzen' 'Replace unsupported Windows'
    $r.Detail = L 'Diese Windows-Version erhält seit Jahren keine Sicherheitsupdates mehr.' 'This Windows version has not received security updates for years.'
    return $r
}

# CISA-Frist (dueDate) auswerten -> Rang (3=überfällig,2=fällig bald,1=zukunft,0=unbekannt),
# Anzeigetext und Farb-Klasse. dueDate kommt als 'yyyy-MM-dd'.
$script:DueSoonDays = 14
function Get-FristInfo([string]$due) {
    $r = [PSCustomObject]@{ Rank = 0; Label = (L '-' '-'); Class = '' }
    if ([string]::IsNullOrWhiteSpace($due)) { return $r }
    $d = $null
    try { $d = [datetime]::ParseExact($due, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture) }
    catch { try { $d = [datetime]$due } catch { return $r } }
    $days = ($d.Date - (Get-Date).Date).Days
    if ($days -lt 0)                    { $r.Rank = 3; $r.Label = (L ("überfällig ({0} T)" -f [Math]::Abs($days)) ("overdue ({0} d)" -f [Math]::Abs($days))); $r.Class = 'warn' }
    elseif ($days -le $script:DueSoonDays) { $r.Rank = 2; $r.Label = (L ("fällig in {0} T" -f $days) ("due in {0} d" -f $days)); $r.Class = 'caution' }
    else                                { $r.Rank = 1; $r.Label = (L ("fällig {0}" -f $due) ("due {0}" -f $due)); $r.Class = '' }
    return $r
}

# Größe lesbar darstellen (ab 1024 GB als TB)
function Format-SizeGB([double]$gb) {
    if ($gb -ge 1024) { return ('{0:N2} TB' -f ($gb / 1024)) }
    return ('{0:N1} GB' -f $gb)
}

# Massenspeicher: ALLE physischen Datenträger (HDD / SSD / NVMe / USB-Sticks / USB-Platten) samt
# ihren Volumes - dynamisch, beliebig viele. Funktioniert ohne Admin; BitLocker-Status und
# SSD-Verschleiß/Temperatur kommen nur mit Admin-Rechten (sonst 'n/a' bzw. leer).
# Fehler werden NICHT verschluckt, sondern in $script:StorageErrors gesammelt (Report + GUI-Log).
function Get-StorageInfo {
    $devices = New-Object System.Collections.Generic.List[object]
    $seen    = @{}
    $blMap   = @{}
    $physMap = @{}
    # Optional (Admin / Storage-Modul): Fehler hier sind normal und werden bewusst nicht gemeldet
    try { foreach ($b in @(Get-BitLockerVolume -EA Stop)) { if ($b.MountPoint) { $blMap[$b.MountPoint.TrimEnd('\')] = (L "$($b.VolumeStatus) / Schutz $($b.ProtectionStatus)" "$($b.VolumeStatus) / protection $($b.ProtectionStatus)") } } } catch {}
    try { foreach ($p in @(Get-PhysicalDisk -EA Stop)) { $physMap["$($p.DeviceId)"] = $p } } catch {}

    $mkVol = {
        param($ld)
        $size = [double]$ld.Size; $free = [double]$ld.FreeSpace; $used = $size - $free
        $pct  = 0; if ($size -gt 0) { $pct = [int][math]::Round($used / $size * 100) }
        $bl   = 'n/a'; if ($blMap.ContainsKey("$($ld.DeviceID)")) { $bl = $blMap["$($ld.DeviceID)"] }
        [PSCustomObject]@{
            Laufwerk  = "$($ld.DeviceID)"
            Label     = "$($ld.VolumeName)"
            FS        = "$($ld.FileSystem)"
            SizeGB    = [math]::Round($size / 1GB, 1)
            FreeGB    = [math]::Round($free / 1GB, 1)
            UsedGB    = [math]::Round($used / 1GB, 1)
            UsedPct   = $pct
            BitLocker = $bl
        }
    }

    # Lokale Festplatten (3) + Wechseldatenträger (2); leere Kartenleser (Size = 0) fallen raus
    $logical = @()
    try { $logical = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2 OR DriveType=3' -EA Stop | Where-Object { $_.Size -gt 0 }) }
    catch { [void]$script:StorageErrors.Add("Win32_LogicalDisk: $($_.Exception.Message)") }

    $drives = @()
    try { $drives = @(Get-CimInstance Win32_DiskDrive -EA Stop | Sort-Object Index) }
    catch { $script:StorageErrors.Add("Win32_DiskDrive: $($_.Exception.Message)") }

    foreach ($dd in $drives) {
        try {
            $vols = New-Object System.Collections.Generic.List[object]
            foreach ($part in @(Get-CimAssociatedInstance -InputObject $dd -ResultClassName Win32_DiskPartition -EA SilentlyContinue)) {
                foreach ($ld in @(Get-CimAssociatedInstance -InputObject $part -ResultClassName Win32_LogicalDisk -EA SilentlyContinue)) {
                    if ($ld.Size -gt 0 -and -not $seen.ContainsKey("$($ld.DeviceID)")) {
                        $seen["$($ld.DeviceID)"] = $true
                        $vols.Add((& $mkVol $ld))
                    }
                }
            }

            $pd    = $physMap["$($dd.Index)"]
            $isUsb = ("$($dd.InterfaceType)" -eq 'USB') -or ("$($dd.PNPDeviceID)" -like 'USBSTOR*') -or ($pd -and "$($pd.BusType)" -eq 'USB')
            $bus   = if ($isUsb) { 'USB' } elseif ($pd -and $pd.BusType) { "$($pd.BusType)" } else { "$($dd.InterfaceType)" }
            $media = if ($pd) { "$($pd.MediaType)" } else { '' }
            $kind  = if ($bus -eq 'NVMe') { 'NVMe-SSD' }
                     elseif ($media -eq 'SSD') { 'SSD' }
                     elseif ($media -eq 'HDD') { 'HDD' }
                     elseif ("$($dd.MediaType)" -match 'Removable') { L 'Wechselmedium' 'Removable media' }
                     else { L 'Datenträger' 'Disk' }
            $health = if ($pd -and $pd.HealthStatus) { "$($pd.HealthStatus)" } elseif ($dd.Status) { "$($dd.Status)" } else { 'n/a' }

            $wear = $null; $temp = $null; $poh = $null
            if ($pd) { try { $rc = $pd | Get-StorageReliabilityCounter -EA Stop; $wear = $rc.Wear; $temp = $rc.Temperature; $poh = $rc.PowerOnHours } catch {} }

            $devSize = 0.0; try { $devSize = [math]::Round([double]$dd.Size / 1GB, 1) } catch {}
            $devices.Add([PSCustomObject]@{
                Index    = $dd.Index
                Model    = ("$($dd.Model)").Trim()
                Kind     = $kind
                Bus      = $bus
                SizeGB   = $devSize
                Health   = $health
                Wear     = $wear
                TempC    = $temp
                PowerOnH = $poh
                Volumes  = $vols.ToArray()
            })
        } catch {
            [void]$script:StorageErrors.Add("$(G 'Datenträger' 'Disk') $($dd.Index): $($_.Exception.Message)")
        }
    }

    # Volumes ohne physische Zuordnung (z. B. VHD, Storage Spaces, Zuordnung fehlgeschlagen) -
    # sorgt auch dafür, dass bei Problemen mit der Zuordnung wenigstens alle Laufwerke erscheinen.
    try {
        $rest = New-Object System.Collections.Generic.List[object]
        foreach ($ld in $logical) { if (-not $seen.ContainsKey("$($ld.DeviceID)")) { $rest.Add((& $mkVol $ld)) } }
        if ($rest.Count -gt 0) {
            $restSize = 0.0; foreach ($rv in $rest) { $restSize += [double]$rv.SizeGB }
            $devices.Add([PSCustomObject]@{
                Index = 999; Model = (L 'Weitere Laufwerke (ohne physische Zuordnung)' 'Other drives (no physical disk mapping)'); Kind = 'Volume'; Bus = '-'
                SizeGB = [math]::Round($restSize, 1); Health = 'n/a'
                Wear = $null; TempC = $null; PowerOnH = $null; Volumes = $rest.ToArray()
            })
        }
    } catch { [void]$script:StorageErrors.Add("$(G 'Restliche Volumes' 'Remaining volumes'): $($_.Exception.Message)") }
    return $devices.ToArray()
}

# Ping per .NET (läuft identisch in Windows PowerShell 5.1 und PowerShell 7; Test-Connection liefert
# je nach Version ResponseTime oder Latency und braucht unter 5.1 WMI). Mittelwert der Antworten in ms.
function Get-PingAvg([string]$Target, [int]$Count = 3, [int]$TimeoutMs = 1500) {
    $times = New-Object System.Collections.Generic.List[double]
    $ping  = New-Object System.Net.NetworkInformation.Ping
    try {
        for ($i = 0; $i -lt $Count; $i++) {
            try { $rep = $ping.Send($Target, $TimeoutMs); if ($rep.Status -eq 'Success') { $times.Add([double]$rep.RoundtripTime) } } catch {}
            if ($i -lt $Count - 1) { Start-Sleep -Milliseconds 200 }
        }
    } finally { $ping.Dispose() }
    if ($times.Count -eq 0) { return $null }
    $sum = 0.0; foreach ($x in $times) { $sum += $x }
    return [math]::Round($sum / $times.Count, 1)
}

# Download-Speedtest: lädt die Testdatei in den Speicher (kein Temp-File -> misst Netz, nicht Platte),
# Zeitmessung ab Antwortbeginn (ohne DNS/TLS-Aufbau), Mbit/s aus der tatsächlich gelesenen Byte-Zahl.
function Measure-DownloadSpeed {
    param([string]$Url, [int]$TimeoutSec = 30)
    $res = [PSCustomObject]@{ Ok = $false; Mbps = 0.0; Bytes = 0L; Seconds = 0.0; Rating = 'n/a'; Class = 'v caution'; Text = (L 'nicht ermittelbar' 'not determinable'); Detail = '' }
    $resp = $null; $stream = $null
    try {
        $sep = '?'; if ($Url -match '\?') { $sep = '&' }
        $req = [System.Net.HttpWebRequest]::Create($Url + $sep + 'cb=' + [DateTime]::UtcNow.Ticks)   # Cache-Buster
        $req.Timeout          = $TimeoutSec * 1000
        $req.ReadWriteTimeout = $TimeoutSec * 1000
        $req.UserAgent        = 'CVEwatch-AssetScan'
        $req.CachePolicy      = New-Object System.Net.Cache.RequestCachePolicy -ArgumentList ([System.Net.Cache.RequestCacheLevel]::NoCacheNoStore)
        try { $req.Proxy = [System.Net.WebRequest]::GetSystemWebProxy(); $req.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials } catch {}
        $resp   = $req.GetResponse()
        $stream = $resp.GetResponseStream()
        $buf    = New-Object byte[] 65536
        $total  = 0L
        $sw     = [System.Diagnostics.Stopwatch]::StartNew()
        while (($n = $stream.Read($buf, 0, $buf.Length)) -gt 0) {
            $total += $n
            if ($sw.Elapsed.TotalSeconds -gt $TimeoutSec) { throw (G 'Zeitüberschreitung beim Download' 'Download timed out') }
        }
        $sw.Stop()
        if ($total -lt 100KB) { throw (G "Testdatei leer oder zu klein ($total Bytes)" "Test file empty or too small ($total bytes)") }
        $sec  = [math]::Max($sw.Elapsed.TotalSeconds, 0.001)
        $mbps = [math]::Round(($total * 8 / 1e6) / $sec, 2)

        $rating = 'Ungenügend'; $cls = 'v warn'
        if     ($mbps -ge 50) { $rating = 'Perfekt';    $cls = 'v good' }
        elseif ($mbps -ge 20) { $rating = 'Gut';        $cls = 'v good' }
        elseif ($mbps -ge 10) { $rating = 'Ok';         $cls = 'v caution' }
        elseif ($mbps -ge 2)  { $rating = 'Mangelhaft'; $cls = 'v warn' }

        $res.Ok = $true; $res.Mbps = $mbps; $res.Bytes = $total; $res.Seconds = [math]::Round($sec, 2)
        $res.Rating = $rating; $res.Class = $cls
        $ratingEn = @{ 'Perfekt' = 'Excellent'; 'Gut' = 'Good'; 'Ok' = 'OK'; 'Mangelhaft' = 'Poor'; 'Ungenügend' = 'Insufficient' }[$rating]
        $res.Text   = L ('{0} ({1:N2} Mbit/s)' -f $rating, $mbps) ('{0} ({1:N2} Mbit/s)' -f $ratingEn, $mbps)
        $res.Detail = L ('{0:N2} MB in {1:N2} s geladen' -f ($total / 1e6), $sec) ('{0:N2} MB downloaded in {1:N2} s' -f ($total / 1e6), $sec)
    } catch {
        $res.Ok = $false; $res.Class = 'v caution'; $res.Text = (L 'nicht ermittelbar' 'not determinable')
        $em = $_.Exception; while ($em.InnerException) { $em = $em.InnerException }   # eigentliche Ursache statt PowerShell-Wrapper
        $res.Detail = "$($em.Message)"
    } finally {
        if ($stream) { try { $stream.Close() } catch {} }
        if ($resp)   { try { $resp.Close() }   catch {} }
    }
    return $res
}

#endregion

#region ============================ SYSTEM-INFO =============================

# --- Administrator-Hinweis: blockiert nie (Rollout-tauglich) ---
#   -RequireAdmin  : ohne Administratorrechte sofort Exit-Code 5 (für Rollouts, die Rechtefehler erkennen sollen)
#   -AllowNonAdmin : still weiterlaufen, die Warnung steht nur im Log und im Bericht
#   sonst, in einer echten interaktiven Konsole: 10 Sekunden Bedenkzeit (N = abbrechen, Enter = sofort starten),
#   danach läuft der Scan von selbst. Ohne Konsole (GUI-Kindprozess, geplante Tasks, Remote, ISE): keine Wartezeit.
if (-not (Test-IsAdmin)) {
    Emit 'system' (G '[!] Nicht als Administrator gestartet: BitLocker-Status, Defender-Ausschlüsse, SSD-Gesundheitswerte sowie Teile der Treiber- und Dienstdaten fehlen, der Scan ist unvollständig.' '[!] Not started as administrator: BitLocker status, Defender exclusions, SSD health values and parts of the driver and service data are missing, the scan is incomplete.') 'Yellow'
    if ($RequireAdmin) {
        Emit 'system' (G '[!] -RequireAdmin ist gesetzt: Abbruch mit Exit-Code 5, es wurde nichts erfasst.' '[!] -RequireAdmin is set: aborting with exit code 5, nothing was collected.') 'Red'
        exit 5
    }
    if (-not $StatusFile -and -not $AllowNonAdmin -and [Environment]::UserInteractive) {
        $canKey = $false
        try { if (-not [Console]::IsInputRedirected) { [void][Console]::KeyAvailable; $canKey = $true } } catch { $canKey = $false }
        if ($canKey) {
            Write-Host (G '    Für den vollen Umfang PowerShell "als Administrator" starten. Ohne Eingabe startet der Scan automatisch.' '    For the full scope, start PowerShell "as administrator". Without input the scan starts automatically.') -ForegroundColor Yellow
            $deadline = (Get-Date).AddSeconds(10); $userAbort = $false
            while ((Get-Date) -lt $deadline) {
                $left = [int][math]::Ceiling(($deadline - (Get-Date)).TotalSeconds)
                Write-Host -NoNewline ((G "`r    Start in {0,2} s - N = abbrechen, Enter = jetzt starten " "`r    Starting in {0,2} s - N = cancel, Enter = start now ") -f $left) -ForegroundColor Yellow
                if ([Console]::KeyAvailable) { $k = [Console]::ReadKey($true); if ($k.Key -eq 'N') { $userAbort = $true }; break }
                Start-Sleep -Milliseconds 200
            }
            Write-Host ''
            if ($userAbort) { Write-Host (G '    Abgebrochen, es wurde noch nichts erfasst.' '    Cancelled, nothing has been collected yet.') -ForegroundColor Yellow; exit 1 }
        }
    }
}

Emit 'system' (G "[*] Erfasse System- und Hardware-Daten ..." "[*] Collecting system and hardware data ...")

try { $CPU = (Get-CimInstance Win32_Processor -EA Stop).Name -join ' / ' } catch { $CPU = 'n/a' }
try { $GPU = ((Get-CimInstance Win32_VideoController -EA Stop).Name | Where-Object { $_ }) -join ' / ' } catch { $GPU = 'n/a' }  
try { $RAM = [math]::Round((Get-CimInstance Win32_ComputerSystem -EA Stop).TotalPhysicalMemory / 1GB, 2) } catch { $RAM = 'n/a' }
# Massenspeicher (dynamisch: alle physischen Datenträger inkl. USB, samt Volumes)
$Storage = @()
$script:StorageErrors = New-Object System.Collections.Generic.List[string]
try { $Storage = @(Get-StorageInfo) } catch { $Storage = @(); [void]$script:StorageErrors.Add("Get-StorageInfo: $($_.Exception.Message)") }
if ($Storage.Count -eq 0 -or $script:StorageErrors.Count -gt 0) {
    Emit 'system' (G "[!] Massenspeicher: $($Storage.Count) Datenträger, Probleme: $($script:StorageErrors -join ' | ')" "[!] Storage: $($Storage.Count) disks, problems: $($script:StorageErrors -join ' | ')") 'Yellow'
}
$StorageSummary = 'n/a'
if ($Storage.Count -gt 0) {
    $StorageSummary = (@(foreach ($dev in $Storage) {
        $vs = (@(foreach ($vol in $dev.Volumes) { (G '{0} {1} GB frei von {2} GB' '{0} {1} GB free of {2} GB') -f $vol.Laufwerk, $vol.FreeGB, $vol.SizeGB }) -join ', ')
        "$(LT $dev.Model) [$(LT $dev.Kind)/$($dev.Bus), $(Format-SizeGB $dev.SizeGB)] $vs"
    }) -join ' | ')
}

if (-not $GPU) { $GPU = 'n/a' }

try {
    $bb = Get-CimInstance Win32_BaseBoard -EA Stop
    $MB = "$($bb.Product) / $($bb.Manufacturer)"
} catch { $MB = 'n/a' }

try {
    $cs = Get-CimInstance Win32_ComputerSystem -EA Stop
    $SystemModel = "$($cs.Model) / $($cs.Manufacturer)"
} catch { $SystemModel = 'n/a' }

try {
    $bios = Get-CimInstance Win32_BIOS -EA Stop
    $BIOS = "$($bios.Name) / $($bios.SMBIOSBIOSVersion)"
} catch { $BIOS = 'n/a' }

# Seriennummer mehrstufig: BIOS -> Gehäuse -> Systemprodukt. Junk-Werte verwerfen.
function Get-CleanSerial {
    $junk = @('to be filled by o.e.m.','default string','system serial number',
              'none','n/a','not applicable','not specified','0','00000000','',
              'chassis serial number','oem','unknown')
    foreach ($cmd in @(
        { (Get-CimInstance Win32_BIOS -EA Stop).SerialNumber },
        { (Get-CimInstance Win32_SystemEnclosure -EA Stop).SerialNumber },
        { (Get-CimInstance Win32_ComputerSystemProduct -EA Stop).IdentifyingNumber }
    )) {
        try {
            $v = (& $cmd | Select-Object -First 1)
            if ($v) { $v = "$v".Trim() }
            if ($v -and ($junk -notcontains $v.ToLowerInvariant())) { return $v }
        } catch {}
    }
    return (L 'n/a (nicht hinterlegt)' 'n/a (not stored)')
}
$Serial = Get-CleanSerial

try {
    $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -EA Stop
    $FullBuild = "$($reg.CurrentMajorVersionNumber).$($reg.CurrentMinorVersionNumber).$($reg.CurrentBuildNumber).$($reg.UBR)"
    $OSName    = if ("$($reg.InstallationType)" -match 'Server') { [string]$reg.ProductName } elseif ([int]$reg.CurrentBuildNumber -lt 22000) { 'Windows 10' } else { 'Windows 11' }
    $OSDisplay = "$OSName  |  Build $FullBuild  |  $($reg.DisplayVersion)"
} catch { $OSDisplay = 'n/a'; $FullBuild = 'n/a' }

# Defender-Signaturen
try {
    $mp = Get-MpComputerStatus -EA Stop
    $DefSig = if ($mp.AntivirusSignatureVersion) { $mp.AntivirusSignatureVersion } else { 'n/a' }
    $old = ($mp.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-1))
    $DefState = L "$DefSig ($(if ($old) { 'älter als 24h' } else { 'aktuell' }))" "$DefSig ($(if ($old) { 'older than 24h' } else { 'current' }))"
} catch { $DefState = L 'n/a (Defender nicht abrufbar)' 'n/a (Defender not available)' }

# Firewall
try {
    $fw = Get-NetFirewallProfile -EA Stop
    $active  = ($fw | Where-Object Enabled -eq $true).Count
    $missing = ($fw | Where-Object Enabled -eq $false).Name -join ', '
    $FwState = if ($active -eq 3) { L '3/3 Profile aktiv' '3/3 profiles active' } else { L "$active/3 aktiv (inaktiv: $missing)" "$active/3 active (inactive: $missing)" }
} catch { $FwState = 'n/a' }

#endregion

#region ======================= SICHERHEITS-POSTURE ==========================

Emit 'posture' (G "[*] Erfasse Sicherheits-Posture ..." "[*] Collecting security posture ...")

# Uptime / letzter Boot (lange Uptime -> Patches evtl. nicht aktiv)
try {
    $os = Get-CimInstance Win32_OperatingSystem -EA Stop
    $LastBoot   = $os.LastBootUpTime
    $UptimeDays = [math]::Round(((Get-Date) - $LastBoot).TotalDays, 1)
    $UptimeState = L "$UptimeDays Tage (Boot: $($LastBoot.ToString('dd.MM.yyyy HH:mm')))" "$UptimeDays days (boot: $($LastBoot.ToString('yyyy-MM-dd HH:mm')))"
} catch { $UptimeState = 'n/a' }

# Ausstehender Neustart (oft = Patches nicht vollständig angewandt)
try {
    $pending = $false
    foreach ($k in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
        if (Test-Path $k) { $pending = $true }
    }
    $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -EA SilentlyContinue).PendingFileRenameOperations
    if ($pfro) { $pending = $true }
    $RebootState = if ($pending) { L 'JA - Neustart ausstehend' 'YES - restart pending' } else { L 'nein' 'no' }
} catch { $RebootState = 'n/a' }

# Letztes installiertes Update
try {
    $lastHf = Get-HotFix -EA Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($lastHf) {
        $daysSince = [math]::Round(((Get-Date) - $lastHf.InstalledOn).TotalDays)
        $PatchState = L "$($lastHf.InstalledOn.ToString('dd.MM.yyyy')) ($($lastHf.HotFixID), vor $daysSince Tagen)" "$($lastHf.InstalledOn.ToString('yyyy-MM-dd')) ($($lastHf.HotFixID), $daysSince days ago)"
    } else { $PatchState = L 'keine Hotfix-Daten' 'no hotfix data' }
} catch { $PatchState = 'n/a' }

# OS-Support: nach Release, Edition und Server/Client (Lebenszyklus-Tabellen siehe Get-OsSupportInfo)
$OSSupportInfo = $null
try {
    $OSSupportInfo = Get-OsSupportInfo ([int]$reg.CurrentBuildNumber) "$($reg.InstallationType)" "$($reg.DisplayVersion)" "$($reg.EditionID)"
    $OSSupport = $OSSupportInfo.Text
} catch { $OSSupport = 'n/a' }

# Secure Boot
try { $SecureBoot = if (Confirm-SecureBootUEFI -EA Stop) { L 'aktiv' 'active' } else { L 'inaktiv' 'inactive' } }
catch { $SecureBoot = L 'n/a (Legacy-BIOS oder keine Rechte)' 'n/a (legacy BIOS or no rights)' }

# BitLocker (Systemlaufwerk)
try {
    $blv = Get-BitLockerVolume -MountPoint $env:SystemDrive -EA Stop
    $BitLocker = L "$($blv.VolumeStatus) / Schutz $($blv.ProtectionStatus)" "$($blv.VolumeStatus) / protection $($blv.ProtectionStatus)"
} catch { $BitLocker = L 'n/a (keine Rechte / nicht verfügbar)' 'n/a (no rights / not available)' }

# TPM
try {
    $tpm = Get-Tpm -EA Stop
    $TPMState = if ($tpm.TpmPresent) { L "vorhanden (aktiviert=$($tpm.TpmEnabled))" "present (enabled=$($tpm.TpmEnabled))" } else { L 'nicht vorhanden' 'not present' }
} catch { $TPMState = 'n/a' }

# RDP aktiviert? (Angriffsfläche)
try {
    $deny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA Stop).fDenyTSConnections
    $RDPState = if ($deny -eq 0) { L 'AKTIVIERT' 'ENABLED' } else { L 'deaktiviert' 'disabled' }
} catch { $RDPState = 'n/a' }

# SMBv1 (klassisches Risiko)
try {
    $SMB1State = if ((Get-SmbServerConfiguration -EA Stop).EnableSMB1Protocol) { L 'AKTIVIERT (Risiko)' 'ENABLED (risk)' } else { L 'deaktiviert' 'disabled' }
} catch { $SMB1State = 'n/a' }

# UAC
try {
    $lua = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -EA Stop).EnableLUA
    $UACState = if ($lua -eq 1) { L 'aktiv' 'active' } else { L 'DEAKTIVIERT (Risiko)' 'DISABLED (risk)' }
} catch { $UACState = 'n/a' }

# Registrierte AV-Produkte (SecurityCenter2 - nur Client-OS)
try {
    $AVState = ((Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -EA Stop).displayName | Select-Object -Unique) -join ', '
    if (-not $AVState) { $AVState = L 'keine registriert' 'none registered' }
} catch { $AVState = L 'n/a (Server-OS?)' 'n/a (server OS?)' }
# Ist neben Defender ein anderer Virenschutz registriert? Dann ist ein abgeschalteter Defender normal (kein Risiko).
$ThirdPartyAV = @("$AVState" -split ',\s*' | Where-Object { $_ -and $_ -notmatch 'Defender|^keine registriert$|^n/a' })

# Läuft der Scan erhöht?
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $AdminState = if ($isAdmin) { L 'ja (vollständiger Scan)' 'yes (complete scan)' } else { L 'nein (Scan evtl. unvollständig)' 'no (scan possibly incomplete)' }
} catch { $AdminState = 'n/a' }

# --- Microsoft Defender im Detail (eigener Block im Report) ---
function Format-DefFlag($v, [bool]$passive, [string]$other = '') {
    if ($null -eq $v) { return $null }
    if ($v) { return (L 'aktiv' 'active') }
    if ($other)   { return (L "aus - Schutz durch $other" "off - protection by $other") }
    if ($passive) { return (L 'aus - Defender passiv (Hinweis)' 'off - Defender passive (notice)') }
    return (L 'DEAKTIVIERT (Risiko)' 'DISABLED (risk)')
}
function Format-DefScanAge($age, [bool]$hint) {
    if ($null -eq $age) { return $null }
    if ([uint64]$age -ge 4294967295) { return (L ('noch nie' + $(if ($hint) { ' (Hinweis)' } else { '' })) ('never' + $(if ($hint) { ' (notice)' } else { '' }))) }
    $n = ($hint -and [uint64]$age -gt 7)
    return (L ("vor $age Tag(en)" + $(if ($n) { ' (Hinweis)' } else { '' })) ("$age day(s) ago" + $(if ($n) { ' (notice)' } else { '' })))
}
$DefenderItems = [ordered]@{}
function Add-Def([string]$k, $v) { if ($null -ne $v -and "$v" -ne '') { $DefenderItems[$k] = $(if (Test-L $v) { $v } else { "$v" }) } }   # zweisprachige Werte bleiben erhalten

try {
    $dm = Get-MpComputerStatus -EA Stop
    $dp = $null; try { $dp = Get-MpPreference -EA Stop } catch {}
    $passive = ("$($dm.AMRunningMode)" -match 'Passive')
    $otherAV = ($ThirdPartyAV -join ', ')

    Add-Def 'Produktversion'  $dm.AMProductVersion
    Add-Def 'Engine-Version'  $dm.AMEngineVersion
    if ($dm.AntivirusSignatureVersion) {
        $sv = "$($dm.AntivirusSignatureVersion)"; $svEn = $sv
        if ($dm.AntivirusSignatureLastUpdated) {
            $sigAge = [int][math]::Floor(((Get-Date) - $dm.AntivirusSignatureLastUpdated).TotalDays)
            $sv   += (' (vom {0}, vor {1} Tag(en))' -f $dm.AntivirusSignatureLastUpdated.ToString('dd.MM.yyyy HH:mm'), $sigAge)
            $svEn += (' (from {0}, {1} day(s) ago)' -f $dm.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm'), $sigAge)
            if ($sigAge -gt 7) { $sv += ' (Risiko)'; $svEn += ' (risk)' } elseif ($sigAge -gt 2) { $sv += ' (Hinweis)'; $svEn += ' (notice)' }
        }
        $sv = L $sv $svEn
        Add-Def 'Signatur-Version' $sv
    }
    if ($dm.AMRunningMode) { Add-Def 'Betriebsmodus' (L ("$($dm.AMRunningMode)" + $(if ($passive) { ' (Hinweis)' } else { '' })) ("$($dm.AMRunningMode)" + $(if ($passive) { ' (notice)' } else { '' }))) }
    Add-Def 'Virenschutz'          (Format-DefFlag $dm.AntivirusEnabled $passive $otherAV)
    Add-Def 'Echtzeitschutz'       (Format-DefFlag $dm.RealTimeProtectionEnabled $passive $otherAV)
    Add-Def 'Verhaltensüberwachung' (Format-DefFlag $dm.BehaviorMonitorEnabled $passive $otherAV)
    Add-Def 'Manipulationsschutz'  (Format-DefFlag $dm.IsTamperProtected $passive $otherAV)

    if ($dp) {
        $maps = switch ([int]$dp.MAPSReporting) { 0 { L 'aus (Hinweis)' 'off (notice)' } 1 { L 'einfach' 'basic' } 2 { L 'erweitert' 'advanced' } default { "$($dp.MAPSReporting)" } }
        Add-Def 'Cloud-Schutz (MAPS)' $maps
        $pua  = switch ([int]$dp.PUAProtection) { 0 { L 'aus (Hinweis)' 'off (notice)' } 1 { L 'aktiv' 'active' } 2 { L 'nur Überwachung' 'audit only' } default { "$($dp.PUAProtection)" } }
        Add-Def 'PUA-Schutz (unerwünschte Apps)' $pua
        $np   = switch ([int]$dp.EnableNetworkProtection) { 0 { L 'aus (Hinweis)' 'off (notice)' } 1 { L 'aktiv' 'active' } 2 { L 'nur Überwachung' 'audit only' } default { "$($dp.EnableNetworkProtection)" } }
        Add-Def 'Netzwerkschutz' $np
        $cfa  = switch ([int]$dp.EnableControlledFolderAccess) { 0 { L 'aus' 'off' } 1 { L 'aktiv' 'active' } 2 { L 'nur Überwachung' 'audit only' } 3 { L 'aktiv (nur Datenträger-Schreibzugriff)' 'active (disk write access only)' } 4 { L 'Überwachung (nur Datenträger)' 'audit (disks only)' } default { "$($dp.EnableControlledFolderAccess)" } }
        Add-Def 'Kontrollierter Ordnerzugriff' $cfa
        $asrCount = @($dp.AttackSurfaceReductionRules_Ids | Where-Object { $_ }).Count
        Add-Def 'ASR-Regeln (Angriffsflächen-Reduzierung)' (L "$asrCount konfiguriert" "$asrCount configured")
        $exAll = @($dp.ExclusionPath) + @($dp.ExclusionExtension) + @($dp.ExclusionProcess) | Where-Object { $_ }
        if (@($exAll | Where-Object { "$_" -match '^N/A' }).Count -gt 0) { Add-Def 'Ausschlüsse' (L 'n/a (Administratorrechte nötig)' 'n/a (administrator rights required)') }
        else { Add-Def 'Ausschlüsse' (L ('{0} konfiguriert (Pfade/Endungen/Prozesse)' -f @($exAll).Count) ('{0} configured (paths/extensions/processes)' -f @($exAll).Count)) }
    }
    Add-Def 'Letzter Quick-Scan' (Format-DefScanAge $dm.QuickScanAge $true)
    Add-Def 'Letzter Full-Scan'  (Format-DefScanAge $dm.FullScanAge $false)
} catch {
    $DefenderItems['Microsoft Defender'] = L 'n/a (nicht abrufbar)' 'n/a (not available)'
}

# --- Zusätzliche Härtungs-Indikatoren ---
# Virtualisierungsbasierte Sicherheit / HVCI / Credential Guard
$VBSState = $HVCIState = $CredGuard = 'n/a'
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -EA Stop
    $dgRunning = @($dg.SecurityServicesRunning)
    $VBSState  = switch ([int]$dg.VirtualizationBasedSecurityStatus) { 2 { L 'läuft' 'running' } 1 { L 'aktiviert, aber nicht gestartet (Hinweis)' 'enabled but not started (notice)' } default { L 'aus (Hinweis)' 'off (notice)' } }
    $HVCIState = if ($dgRunning -contains 2) { L 'läuft' 'running' } else { L 'nicht aktiv (Hinweis)' 'not active (notice)' }
    $CredGuard = if ($dgRunning -contains 1) { L 'läuft' 'running' } else { L 'nicht aktiv (Enterprise-Funktion)' 'not active (Enterprise feature)' }
} catch {}

# LSA-Schutz (RunAsPPL) - fehlender Wert heißt nicht zwingend "aus" (neuere Windows-11-Builds), daher vorsichtig formuliert
$LsaState = 'n/a'
try {
    $ppl = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -EA Stop).RunAsPPL
    $LsaState = if ([int]$ppl -ge 1) { L 'aktiv' 'active' } else { L 'aus (Hinweis)' 'off (notice)' }
} catch { $LsaState = L 'nicht explizit konfiguriert (Hinweis)' 'not explicitly configured (notice)' }

# NTLM-Kompatibilitätslevel
$NtlmState = 'n/a'
try {
    $lm = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -EA Stop).LmCompatibilityLevel
    $NtlmState = if ([int]$lm -lt 3) { L "Level $lm - LM/NTLMv1 möglich (Risiko)" "Level $lm - LM/NTLMv1 possible (risk)" } else { L "Level $lm (NTLMv2 wird gesendet)" "Level $lm (NTLMv2 is sent)" }
} catch { $NtlmState = L 'Windows-Standard (nicht explizit gesetzt)' 'Windows default (not explicitly set)' }

# Autologon
$AutoLogonState = L 'deaktiviert' 'disabled'
try {
    $al = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -EA Stop).AutoAdminLogon
    if ("$al" -eq '1') { $AutoLogonState = L 'aktiv (Risiko)' 'active (risk)' }
} catch {}

# Gast-Konto (RID 501, sprachunabhängig)
$GuestState = 'n/a'
try {
    $gu = Get-LocalUser -EA Stop | Where-Object { $_.SID.Value -like 'S-1-5-21-*-501' } | Select-Object -First 1
    if ($gu) { $GuestState = if ($gu.Enabled) { L 'AKTIVIERT (Risiko)' 'ENABLED (risk)' } else { L 'deaktiviert' 'disabled' } }
} catch {}

# Lokale Administratoren (Gruppe per SID, sprachunabhängig)
$LocalAdmins = 'n/a'
try {
    $ladm = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -EA Stop)
    $la = '{0}: {1}' -f $ladm.Count, (($ladm | ForEach-Object { $_.Name }) -join ', ')
    $LocalAdmins = if ($ladm.Count -gt 3) { L "$la (Hinweis)" "$la (notice)" } else { $la }
} catch {}

# Benutzerdefinierte SMB-Freigaben (ohne Admin-Shares wie C$); Fallback auf Win32_Share, falls das SMB-Modul fehlt
$SmbShares = 'n/a'
$shareNames = $null
try { $shareNames = @(Get-SmbShare -Special $false -EA Stop | ForEach-Object { $_.Name }) } catch {}
if ($null -eq $shareNames) {
    try { $shareNames = @(Get-CimInstance Win32_Share -EA Stop | Where-Object { $_.Type -eq 0 } | ForEach-Object { $_.Name }) } catch {}
}
if ($null -ne $shareNames) {
    $SmbShares = if ($shareNames.Count -eq 0) { L 'keine benutzerdefinierten Freigaben' 'no custom shares' } else { '{0}: {1}' -f $shareNames.Count, ($shareNames -join ', ') }
}

# Geräte-Einbindung (Entra ID / Domäne) laut dsregcmd
$JoinState = 'n/a'
try {
    $ds = @(& "$env:SystemRoot\System32\dsregcmd.exe" /status 2>$null)
    $getKey = {
        param($key)
        $m = $ds | Select-String -Pattern ('^\s*' + $key + '\s*:\s*(\w+)') | Select-Object -First 1
        if ($m) { $m.Matches[0].Groups[1].Value } else { '' }
    }
    $aadJoined = & $getKey 'AzureAdJoined'
    $domJoined = & $getKey 'DomainJoined'
    $jParts = @()
    if ($aadJoined -eq 'YES') { $jParts += 'Entra ID (Azure AD)' }
    if ($domJoined -eq 'YES') { $jParts += 'Active-Directory-Domäne' }
    $JoinState = if ($jParts.Count -gt 0) { L ($jParts -join ' + ') (($jParts -join ' + ') -replace 'Active-Directory-Domäne', 'Active Directory domain') } elseif ($aadJoined -or $domJoined) { L 'nicht eingebunden (Workgroup)' 'not joined (workgroup)' } else { 'n/a' }
} catch {}

# Offene (lauschende) TCP-Ports auf nicht-lokalen Adressen -> Angriffsfläche
$ListenPorts = @()
try {
    $ListenPorts = Get-NetTCPConnection -State Listen -EA Stop |
        Where-Object { $_.LocalAddress -notin @('127.0.0.1','::1') } |
        ForEach-Object {
            [PSCustomObject]@{
                Port    = $_.LocalPort
                Address = $_.LocalAddress
                Process = (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName
            }
        } | Group-Object Port | ForEach-Object {
            $procs = @($_.Group | ForEach-Object { $_.Process } | Where-Object { $_ } | Select-Object -Unique)
            [PSCustomObject]@{
                Port        = [int]$_.Name
                Address     = (@($_.Group | ForEach-Object { $_.Address } | Select-Object -Unique) -join ', ')
                Process     = ($procs -join ', ')
                ProcessList = $procs
            }
        } | Sort-Object Port
} catch {}

#endregion

#region ============================ NETZWERK ================================

Emit 'net' (G "[*] Erfasse Netzwerk-Daten ..." "[*] Collecting network data ...")

$LocalIP=$LocalMAC=$LocalDNS=$Gateway=$OutIP=$Kind='n/a'; $PingMs=$GwMs=''

try {
    $idx = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and -not $_.SkipAsSource } |
        Select-Object -First 1 -ExpandProperty InterfaceIndex

    if ($idx) {
        $adp = Get-NetAdapter -InterfaceIndex $idx -EA SilentlyContinue
        $Kind = if ($adp.InterfaceDescription -match 'Wi(-| )?Fi|WLAN|Wireless') { L 'WLAN' 'Wi-Fi' } else { 'LAN' }

        $LocalIP  = (Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 |
                     Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and -not $_.SkipAsSource } |
                     Select-Object -First 1 -ExpandProperty IPAddress)
        $LocalMAC = $adp.MacAddress
        $LocalDNS = ((Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4).ServerAddresses |
                     Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }) -join ', '
    }
    $Gateway = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -EA SilentlyContinue | Select-Object -First 1 -ExpandProperty NextHop)
} catch {}

# Öffentliche IP: OPT-IN (-PublicIP / GUI-Option). Ohne Opt-in wird dafür nichts nach außen gesendet.
if ($PublicIP) {
    Emit 'net' ((G '[*] Ermittle öffentliche IP ({0}) ...' '[*] Determining public IP ({0}) ...') -f ((@($OutgoingIPSources | ForEach-Object { ([uri]$_).Host })) -join ' / '))
    foreach ($src in $OutgoingIPSources) {
        try { $OutIP = (Invoke-RestMethod -Uri $src -TimeoutSec 3).Trim(); if ($OutIP) { break } } catch {}
    }
} else { $OutIP = L 'nicht abgefragt (Option aus)' 'not queried (option off)' }

# Internet-Latenz: OPT-IN (-Latency / GUI-Option). Der Ping an das Gateway bleibt lokal und läuft immer.
if ($Latency) {
    Emit 'net' ((G '[*] Messe Latenz ({0}) ...' '[*] Measuring latency ({0}) ...') -f ($PingTargets -join ' / '))
    foreach ($t in $PingTargets) {
        $ms = Get-PingAvg $t $PingCount
        if ($null -ne $ms) { $PingMs = "$ms ms -> $t"; break }
    }
    if (-not $PingMs) { $PingMs = L 'keine Antwort (ICMP evtl. gesperrt)' 'no answer (ICMP possibly blocked)' }
} else { $PingMs = L 'nicht gemessen (Option aus)' 'not measured (option off)' }
if ($Gateway -and $Gateway -ne 'n/a') {
    $gwHost = ("$Gateway" -split '[,;\s]+' | Where-Object { $_ } | Select-Object -First 1)
    $ms = Get-PingAvg $gwHost $PingCount
    $GwMs = if ($null -ne $ms) { "$ms ms" } else { L 'keine Antwort' 'no answer' }
}

# Download-Speedtest (OPT-IN: nur mit -SpeedTest bzw. GUI-Option)
$Speed = $null
if (-not ($PublicIP -or $Latency -or $SpeedTest)) { Emit 'net' (G '[*] Keine Tests nach außen aktiv (öffentliche IP, Latenz, Speedtest sind Opt-in).' '[*] No outbound tests active (public IP, latency, speed test are opt-in).') }
if ($SpeedTest) {
    Emit 'net' ((G '[*] Download-Speedtest ({0}) ...' '[*] Download speed test ({0}) ...') -f $SpeedTestUrl)
    $Speed = Measure-DownloadSpeed -Url $SpeedTestUrl -TimeoutSec $SpeedTestTimeoutSec
    if ($Speed.Ok) { Emit 'net' "[*] Download: $(LT $Speed.Text) - $(LT $Speed.Detail)" }
    else           { Emit 'net' ((G '[!] Speedtest fehlgeschlagen: ' '[!] Speed test failed: ') + $Speed.Detail) 'Yellow' }
}

#endregion

#region ============================ INVENTAR-SCAN ===========================

Emit 'inv' (G "[*] Inventarisiere installierte Software ..." "[*] Taking inventory of installed software ...")
$inv = New-Object System.Collections.Generic.List[object]

function Add-Item($name,$version,$vendor,$source,$path) {
    if ([string]::IsNullOrWhiteSpace($name)) { return }
    $script:inv.Add([PSCustomObject]@{
        Name = $name.Trim(); Version = "$version".Trim(); Manufacturer = "$vendor".Trim()
        Source = $source; Path = $path
    })
}

# Meldet pro Quelle, wie viele Einträge seit dem letzten Aufruf dazugekommen sind (Konsole + GUI-Protokoll)
$script:invLast = 0
function Emit-InvStep([string]$Label, [string]$Note = '') {
    $n = $script:inv.Count - $script:invLast
    $script:invLast = $script:inv.Count
    if ($n -gt 0) { Emit 'inv' ("[*] ${Label}: $n " + (G 'Einträge' 'entries') + $Note) }
    else          { Emit 'inv' ("[!] ${Label}: 0 " + (G 'Einträge' 'entries') + $Note) 'Yellow' }
}

# 1) Registry (inkl. Publisher!)  -- BUGFIX ggü. v1: Hersteller wird übernommen
foreach ($p in @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
    try {
        foreach ($i in (Get-ItemProperty $p -EA SilentlyContinue)) {
            if ($i.DisplayName -and -not $i.SystemComponent) {
                Add-Item $i.DisplayName $i.DisplayVersion $i.Publisher 'Registry' 'n/a'
            }
        }
    } catch {}
}

Emit-InvStep 'Registry'

# 1b) Software weiterer, gerade angemeldeter Benutzer (nur für diesen Benutzer installiert, z. B. VS Code User Setup, Zoom, Chrome im Profil).
#     Deren Registry ist unter HKEY_USERS\<SID> bereits geladen: nur LESEN, nichts einhängen. Als SYSTEM ist HKCU sonst
#     der Zweig von SYSTEM selbst, und auch ein Admin-Lauf sieht über HKCU nur das eigene Profil. Ohne Administratorrechte
#     verweigert Windows den Zugriff auf fremde Zweige - dann bleibt es still bei 0.
$script:InvOtherUsers = New-Object System.Collections.Generic.List[string]
try {
    $curSid = ''; try { $curSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch {}
    $userHives = @(Get-ChildItem 'Registry::HKEY_USERS' -EA SilentlyContinue |
                   Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-[\d-]+$' -and $_.PSChildName -ne $curSid })   # lokale/AD-Konten (S-1-5-21) und Entra-ID-Konten (S-1-12-1), ohne *_Classes
    foreach ($h in $userHives) {
        $sid = $h.PSChildName
        $acct = $sid; try { $acct = ([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value } catch {}
        $before = $script:inv.Count
        try {
            foreach ($i in (Get-ItemProperty "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue)) {
                if ($i.DisplayName -and -not $i.SystemComponent) {
                    Add-Item $i.DisplayName $i.DisplayVersion $i.Publisher 'Registry' "HKU\$acct"
                }
            }
        } catch {}
        if ($script:inv.Count -gt $before) { $script:InvOtherUsers.Add($acct) }
    }
} catch {}

# Nur melden, wenn es etwas gab - auf Ein-Benutzer-Rechnern sonst bei jedem Lauf eine gelbe "0 Einträge"-Warnung
if ($script:InvOtherUsers.Count -gt 0) { Emit-InvStep (G 'Registry (weitere angemeldete Benutzer)' 'Registry (other signed-in users)') " ($($script:InvOtherUsers -join ', '))" }

# 2) Winget  (UTF-8 erzwingen gegen Locale-/Spinner-Probleme)
$wingetOk = [bool](Get-Command winget -EA SilentlyContinue)
try {
    $prevEnc = [Console]::OutputEncoding
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $wg = winget list --source winget --accept-source-agreements --disable-interactivity 2>$null
    [Console]::OutputEncoding = $prevEnc
    $started = $false
    foreach ($line in $wg) {
        if ($line -match '^-{3,}') { $started = $true; continue }   # Trennlinie = ab hier Daten
        if (-not $started) { continue }
        if ($line -notmatch '\S') { continue }
        $parts = ($line -split '\s{2,}') | Where-Object { $_ }
        if ($parts.Count -ge 2) { Add-Item $parts[0] $parts[1] '' 'Winget' 'n/a' }
    }
} catch {}

Emit-InvStep 'Winget' $(if (-not $wingetOk) { (G ' (winget nicht installiert)' ' (winget not installed)') } else { '' })

# 3) AppX (Store-Apps) - mit Fallbacks, weil Get-AppxPackage still scheitern kann (z. B. PowerShell 7 ohne
#    Appx-Modul oder ein vom Elternprozess geerbter PSModulePath). Das Ergebnis steht im Log.
$appxCount = 0; $appxSrc = 'Get-AppxPackage'; $appxErr = ''
try {
    foreach ($a in @(Get-AppxPackage -EA Stop)) { Add-Item $a.Name $a.Version $a.Publisher 'AppX' 'n/a'; $appxCount++ }
} catch { $appxErr = "$($_.Exception.Message)" }
if ($appxCount -eq 0 -and $PSVersionTable.PSVersion.Major -ge 6) {
    # PowerShell 7: das Appx-Modul gibt es nur in Windows PowerShell -> über die Kompatibilitätsschicht laden
    try {
        Import-Module Appx -UseWindowsPowerShell -WarningAction SilentlyContinue -EA Stop
        foreach ($a in @(Get-AppxPackage -EA Stop)) { Add-Item $a.Name $a.Version $a.Publisher 'AppX' 'n/a'; $appxCount++ }
        if ($appxCount -gt 0) { $appxSrc = (G 'Get-AppxPackage über Windows-PowerShell-Kompatibilität' 'Get-AppxPackage via Windows PowerShell compatibility') }
    } catch { if (-not $appxErr) { $appxErr = "$($_.Exception.Message)" } }
}
if ($appxCount -eq 0) {
    # Fallback ohne Modul: Paketliste aus der Registry (Name und Version stehen im Schlüsselnamen,
    # z. B. Microsoft.WindowsStore_22209.1401.2.0_x64__8wekyb3d8bbwe); der Hersteller ist dort nicht lesbar.
    try {
        $repo = 'HKLM:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages'
        foreach ($k in @(Get-ChildItem $repo -EA Stop)) {
            if ($k.PSChildName -match '^(?<n>.+?)_(?<v>\d+(?:\.\d+)+)_(?<a>[^_]*)_(?<r>[^_]*)_(?<p>[^_]+)$') {
                Add-Item $Matches['n'] $Matches['v'] '' 'AppX' 'n/a'; $appxCount++
            }
        }
        if ($appxCount -gt 0) { $appxSrc = 'Registry-Fallback' }
    } catch { if (-not $appxErr) { $appxErr = "$($_.Exception.Message)" } }
}
if ($appxCount -gt 0) { Emit 'inv' ((G "[*] AppX: {0} Pakete erfasst ({1})" "[*] AppX: {0} packages collected ({1})") -f $appxCount, $appxSrc) }
else                  { Emit 'inv' ((G "[!] AppX: keine Pakete ermittelt. Grund: {0} (Host: PowerShell {1})" "[!] AppX: no packages found. Reason: {0} (host: PowerShell {1})") -f $appxErr, $PSVersionTable.PSVersion) 'Yellow' }

$script:invLast = $script:inv.Count   # AppX meldet sich oben selbst mit Quelle bzw. Fehlergrund

# 4) Laufende Prozesse (mit Datei-Version)
try {
    foreach ($pr in (Get-Process -EA SilentlyContinue | Where-Object { $_.Path })) {
        try {
            $vi = (Get-Item $pr.Path -EA Stop).VersionInfo
            Add-Item $pr.Name $vi.ProductVersion $vi.CompanyName 'Process' $pr.Path
        } catch {}
    }
} catch {}

Emit-InvStep 'Process' (G ' (laufende Prozesse mit Dateipfad, vor Deduplizierung)' ' (running processes with file path, before deduplication)')

# 5) Dienste (ohne Version -> nicht KEV-matchbar, aber im Inventar)
try { foreach ($s in (Get-Service -EA SilentlyContinue)) { Add-Item $s.DisplayName 'n/a' '' 'Service' 'n/a' } } catch {}

Emit-InvStep 'Service'

# 6) Treiber (mit Version + Hersteller -> KEV-relevant, Stichwort BYOVD)
try {
    foreach ($d in (Get-CimInstance Win32_PnPSignedDriver -EA SilentlyContinue)) {
        if ($d.DeviceName) { Add-Item $d.DeviceName $d.DriverVersion $d.Manufacturer 'Driver' $d.InfName }
    }
} catch {}

Emit-InvStep 'Driver'

# Namen normalisieren
foreach ($i in $inv) { $i.Name = Normalize-SoftwareName $i.Name }

# Dedup pro Quelle nach Name|Version
$seen = @{}; $invClean = New-Object System.Collections.Generic.List[object]
foreach ($i in $inv) {
    $k = "$($i.Source)|$($i.Name)|$($i.Version)".ToLowerInvariant()
    if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $invClean.Add($i) }
}

$counter = 0
foreach ($i in $invClean) { $counter++; $i | Add-Member -NotePropertyName Display -NotePropertyValue ("{0} {1,-9} {2}" -f $counter,$i.Source.ToUpper(),$i.Name) -Force }
$invClean | Export-Csv $CsvPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'

$srcCounts = $invClean | Group-Object Source | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" }
Emit 'inv' ((G "[*] Inventar gesamt: {0} Einträge nach Deduplizierung ({1})" "[*] Inventory total: {0} entries after deduplication ({1})") -f $invClean.Count, ($srcCounts -join ', ')) 'Green'

#endregion

#region ============================ KEV-KATALOG ============================

$kev = $null; $kevSource = ''; $kevDate = ''; $KevSkipped = $false
if ($NoKev) {
    Emit 'kev' (G "[*] KEV-Abgleich übersprungen (-NoKev) - nur Inventar & Posture." "[*] KEV matching skipped (-NoKev) - inventory & posture only.")
    $KevSkipped = $true
} else {
    Emit 'kev' (G "[*] Lade CISA KEV-Katalog ..." "[*] Loading CISA KEV catalog ...")

    # 1) Cache NUR nutzen, wenn ausdrücklich gewünscht (-UseCache) und frisch genug.
#    Standard ist BEWUSST der frische Download: der KEV-Katalog kann jederzeit eine
#    neue, gerade ausgenutzte CVE enthalten - "top aktuell" ist Pflicht, nicht Kür.
if ($UseCache -and (Test-Path $KevCache)) {
    $ageH = ((Get-Date) - (Get-Item $KevCache).LastWriteTime).TotalHours
    if ($ageH -lt $KevCacheTtlHours) {
        try {
            $kev = Get-Content $KevCache -Raw | ConvertFrom-Json
            if ($kev.vulnerabilities) { $kevSource = "Cache ($([int]$ageH)h alt, -UseCache)"; $kevDate = $kev.dateReleased }
            else { $kev = $null }
        } catch { $kev = $null }
    }
    if ($kev) { Write-Host (G "    aus Cache (-UseCache, jünger als ${KevCacheTtlHours}h)." "    from cache (-UseCache, younger than ${KevCacheTtlHours}h).") -ForegroundColor DarkGray }
}

# 2) Standard: frisch herunterladen und Cache erneuern
if (-not $kev) {
    foreach ($url in $KevSources) {
        try {
            $raw = Invoke-WebRequest -Uri $url -TimeoutSec 20 -UseBasicParsing
            $tmp = $raw.Content | ConvertFrom-Json
            if ($tmp.vulnerabilities) {
                $kev = $tmp; $kevSource = $url; $kevDate = $tmp.dateReleased
                try { $raw.Content | Out-File $KevCache -Encoding UTF8 } catch {}
                break
            }
        } catch { Write-Host ((G '    Quelle nicht erreichbar: ' '    Source unreachable: ') + $url) -ForegroundColor DarkYellow }
    }
}

# 3) Notfall-Fallback: veralteter Cache besser als nichts
if (-not $kev -and (Test-Path $KevCache)) {
    try {
        $kev = Get-Content $KevCache -Raw | ConvertFrom-Json
        $ageH = [int]((Get-Date) - (Get-Item $KevCache).LastWriteTime).TotalHours
        $kevSource = "Cache (veraltet, ${ageH}h)"; $kevDate = $kev.dateReleased
        Write-Host (G "    Download fehlgeschlagen - nutze veralteten Cache (${ageH}h alt)." "    Download failed - using outdated cache (${ageH}h old).") -ForegroundColor DarkYellow
    } catch {}
}
    if (-not $kev) { Write-Host (G "[!] KEV nicht abrufbar - Report wird ohne Abgleich erstellt." "[!] KEV unreachable - report is created without matching.") -ForegroundColor Red }

    $kevCount = if ($kev) { @($kev.vulnerabilities).Count } else { 0 }
    Write-Host ((G "    {0} KEV-Einträge geladen." "    {0} KEV entries loaded.") -f $kevCount) -ForegroundColor DarkGray
}
$kevCount = if ($kev) { @($kev.vulnerabilities).Count } else { 0 }

#endregion

#region ============================ KEV-MATCHING ===========================

Emit 'match' (G "[*] Gleiche Inventar mit KEV ab ..." "[*] Matching inventory against KEV ...")

# KEV-Index, Inventar-Einträge und Abgleich: Logik und Tabellen stehen im MATCHER-KERN (Hilfsfunktionen).
$kevIndex = Build-KevIndex $(if ($kev) { $kev.vulnerabilities } else { @() })
if ($kev) {
    Emit 'match' ((G "    {0} von {1} KEV-Einträgen per Programmname abgleichbar; {2} betreffen Windows selbst (Build-Abgleich über die NVD)." "    {0} of {1} KEV entries matchable by program name; {2} concern Windows itself (build check via the NVD).") -f $script:KevStats.Indexed, $script:KevStats.Total, $script:KevStats.OsEntries) 'DarkGray'
}

# Inventar für Matching: distinkte Produkte (Version egal), reichhaltigsten Record behalten
# Registry/AppX: jede installierte Version einzeln (z. B. zwei Java- oder Python-Versionen nebeneinander - die ältere
# kann die verwundbare sein). Winget/Prozesse/Treiber nur, wenn das Programm dort noch nicht vorkommt (sonst doppelte Karten
# durch abweichende Versionsschreibweisen).
$matchInv = @{}; $invNames = @{}
foreach ($i in $invClean) {
    if ($i.Source -notin 'Registry', 'AppX') { continue }
    $nk = $i.Name.ToLowerInvariant(); $invNames[$nk] = $true
    $vk = "$nk|$("$($i.Version)".Trim().ToLowerInvariant())"
    if (-not $matchInv.ContainsKey($vk)) { $matchInv[$vk] = New-MatchItem $i.Name $i.Version $i.Manufacturer $i.Source }
}
foreach ($i in $invClean) {
    if ($i.Source -in 'Registry', 'AppX', 'Service') { continue }      # Dienste: ohne Version für KEV wertlos
    $nk = $i.Name.ToLowerInvariant()
    if (-not $invNames.ContainsKey($nk)) { $invNames[$nk] = $true; $matchInv[$nk] = New-MatchItem $i.Name $i.Version $i.Manufacturer $i.Source }
}
Find-KevHits $matchInv.Values $kevIndex

# Windows-Betriebssystem: Build-Abgleich der KEV-Einträge zu Windows selbst (braucht den NVD-Versionsabgleich)
$script:OsCheck = @{ Done = $false; Why = ''; Name = ''; Key = ''; Build = ''; Old = 0; Total = 0; Eol = $false; Tally = $null }
if (-not $kev)                 { $script:OsCheck.Why = L 'KEV-Abgleich übersprungen' 'KEV matching skipped' }
elseif ($NoOsCheck)            { $script:OsCheck.Why = L 'mit -NoOsCheck abgeschaltet' 'switched off with -NoOsCheck' }
elseif (-not $ResolveVersions) { $script:OsCheck.Why = L 'der NVD-Versionsabgleich ist aus (ohne ihn ist kein Build-Abgleich möglich)' 'the NVD version check is off (no build check is possible without it)' }
elseif (-not $reg -or -not $reg.CurrentBuildNumber) { $script:OsCheck.Why = L 'der Windows-Build konnte nicht gelesen werden' 'the Windows build could not be read' }
else {
    $osRel = Get-OsRelease ([int]$reg.CurrentBuildNumber) "$($reg.InstallationType)" "$($reg.DisplayVersion)"
    if (-not $osRel) { $script:OsCheck.Why = L "das Windows-Release ist nicht zugeordnet (Build $FullBuild)" "the Windows release is not mapped (build $FullBuild)" }
    elseif ($osRel.Eol) {
        $script:OsCheck.Eol = $true; $script:OsCheck.Name = $osRel.Name
        $script:OsCheck.Why = L "$($osRel.Name) erhält keine regulären Updates mehr; ein Build-Abgleich wäre dort nicht belastbar (die NVD führt keine Build-Grenzen)" "$($osRel.Name) no longer receives regular updates; a build check would not be reliable there (the NVD lists no build boundaries)"
    } else {
        $osItem = New-OsMatchItem $osRel $FullBuild "$($reg.EditionID)"
        Add-OsHits $osItem $kevIndex ([bool]$OsAllYears)
        $script:OsCheck.Done = $true; $script:OsCheck.Name = $osRel.Name; $script:OsCheck.Key = $osRel.Key; $script:OsCheck.Build = $FullBuild
        $script:OsCheck.Old = $osItem.OsOld; $script:OsCheck.Total = $osItem.Hits.Count + $osItem.OsOld
        if ($osItem.Hits.Count -gt 0) { $matchInv['__os__'] = $osItem }
    }
}

# Nur Produkte mit Treffern, sortiert: Ransomware -> Konfidenz -> Trefferzahl
$rank = @{ 'Hoch'=3; 'Mittel'=2; 'Niedrig'=1 }
$matched = $matchInv.Values | Where-Object { $_.Hits.Count -gt 0 } | ForEach-Object {
    $best = ($_.Hits | ForEach-Object { $rank[$_.Confidence] } | Measure-Object -Maximum).Maximum
    $_ | Add-Member -NotePropertyName HasRansom  -NotePropertyValue ([bool]($_.Hits | Where-Object Ransom)) -Force
    $_ | Add-Member -NotePropertyName BestRank    -NotePropertyValue $best -Force
    $_
} | Sort-Object @{E={$_.HasRansom};D=$true}, @{E={$_.BestRank};D=$true}, @{E={$_.Hits.Count};D=$true}, Name

$matchedArr = @($matched)
$totalCVEs  = ($matchedArr | ForEach-Object { $_.Hits.Count } | Measure-Object -Sum).Sum
$ransomProducts = @($matchedArr | Where-Object HasRansom).Count

#endregion

#region ===================== VERSIONS-ABGLEICH (NVD) ========================

$affectedCount = 0; $affectedProducts = 0; $VersionResolved = $false; $NvdReachable = $true
if ($ResolveVersions -and $matchedArr.Count -gt 0) {
    Emit 'nvd' (G "[*] Löse Versionsbereiche über die NVD auf ..." "[*] Resolving version ranges via the NVD ...")
    $VersionResolved = $true

    # persistenten CPE-Cache laden (Format: { CVE: { f:'yyyy-MM-dd', r:[...ranges...], s:CVSS-Score, sv:Schweregrad, sver:CVSS-Version } })
    $script:NvdCacheData = @{}
    $cacheIn = if (Test-Path $NvdCache) { $NvdCache } elseif (Test-Path $NvdCacheLegacy) { $NvdCacheLegacy } else { $null }
    if ($cacheIn) {
        try { (Get-Content $cacheIn -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $script:NvdCacheData[$_.Name] = $_.Value } } catch {}
    }
    $script:NvdFailed = New-Object System.Collections.Generic.HashSet[string]
    $script:NvdFresh  = New-Object System.Collections.Generic.HashSet[string]   # in DIESEM Lauf frisch geholt (Memoisierung)
    $script:NvdFirstErr = ''; $script:NvdFirstErrCode = 0   # erster echter Fehler (für Diagnose)

    # CPE-Bereiche bereits länger bekannter KEV-CVEs ändern sich kaum: sie dürfen auch ohne -UseCache aus dem Cache kommen
    # (höchstens $NvdCacheTtlDays alt). Neue KEV-CVEs werden weiterhin immer frisch geholt.
    $script:NvdStaleOk = New-Object System.Collections.Generic.HashSet[string]
    if ($NvdStaleOkDays -gt 0 -and $kev) {
        $staleLim = (Get-Date).AddDays(-$NvdStaleOkDays)
        foreach ($kv in $kev.vulnerabilities) { try { if ([datetime]$kv.dateAdded -lt $staleLim) { [void]$script:NvdStaleOk.Add([string]$kv.cveID) } } catch {} }
    }
    # --- NVD-Antwort (vulnerabilities[i].cve) -> CPE-Bereiche + CVSS; gemeinsam für Einzel- und Sammelabruf ---
    function ConvertFrom-NvdCve($CveObj) {
        # Bereiche direkt im kompakten Textformat (siehe Get-NvdCacheRanges) - spart beim Sammelabruf zehntausende Objekte
        $list = New-Object System.Collections.Generic.List[string]
        foreach ($cfg in $CveObj.configurations) {
            foreach ($node in $cfg.nodes) {
                foreach ($cm in $node.cpeMatch) {
                    if (-not $cm.vulnerable) { continue }
                    $p = ($cm.criteria -split ':')
                    $exact = if ($p.Count -ge 6 -and $p[5] -notin @('*','-')) { $p[5] } else { $null }
                    $prod  = if ($p.Count -ge 5) { $p[4] } else { '' }
                    $list.Add("$prod|$exact|$($cm.versionStartIncluding)|$($cm.versionStartExcluding)|$($cm.versionEndIncluding)|$($cm.versionEndExcluding)")
                }
            }
        }
        # CVSS-Basiswert + Schweregrad aus derselben Antwort (kein Zusatz-Request): v4.0 > v3.1 > v3.0 > v2, bevorzugt die NVD-eigene (Primary) Bewertung
        $sc = $null; $sv = ''; $sver = ''
        try {
            $mt = $CveObj.metrics
            foreach ($mk in 'cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2') {
                $ml = @($mt.$mk | Where-Object { $_ })
                if ($ml.Count -eq 0) { continue }
                $pk = $ml | Where-Object { $_.type -eq 'Primary' } | Select-Object -First 1
                if (-not $pk) { $pk = $ml[0] }
                $sc = [double]$pk.cvssData.baseScore
                $sv = if ($mk -eq 'cvssMetricV2') { "$($pk.baseSeverity)" } else { "$($pk.cvssData.baseSeverity)" }
                $sver = if ($mk -eq 'cvssMetricV2') { '2.0' } else { "$($pk.cvssData.version)" }
                break
            }
        } catch { $sc = $null }
        [PSCustomObject]@{ C = $list.ToArray(); S = $sc; Sv = $sv; Sver = $sver }
    }
    # Kompaktes Cache-Format (Feld c): je Bereich 'Produkt|Exact|VSI|VSE|VEI|VEE' (Text statt Objekt -> schnelles JSON auch in PS 5.1).
    # Get-NvdCacheRanges macht daraus wieder Objekte (Product/Exact/VSI/VSE/VEI/VEE), einmal pro CVE und Lauf.
    $script:NvdExpanded = @{}
    function Get-NvdCacheRanges([string]$cve) {
        $e = $script:NvdCacheData[$cve]
        if ($null -eq $e) { return $null }
        if ($null -eq $e.c) { return $e.r }                       # altes Format (Objekte)
        if (-not $script:NvdExpanded.ContainsKey($cve)) {
            $script:NvdExpanded[$cve] = @(foreach ($t in @($e.c)) {
                $q = ([string]$t).Split('|')
                if ($q.Count -lt 6) { continue }
                [PSCustomObject]@{
                    Product = $q[0]
                    Exact = $(if ($q[1]) { $q[1] } else { $null }); VSI = $(if ($q[2]) { $q[2] } else { $null }); VSE = $(if ($q[3]) { $q[3] } else { $null })
                    VEI   = $(if ($q[4]) { $q[4] } else { $null }); VEE = $(if ($q[5]) { $q[5] } else { $null })
                }
            })
        }
        return $script:NvdExpanded[$cve]
    }

    # --- NVD-Sammelabruf: alle KEV-CVEs (hasKev) seitenweise, danach nur Änderungen (lastModStartDate/-EndDate, max. 120 Tage) ---
    # Erfolg -> Einträge mit b=1 gelten als aktuell (kein Einzelabruf, kein Limit). Fehlschlag -> bisheriger Einzelabruf als Fallback.
    # Der Sync-Stand wird erst zusammen mit dem Cache geschrieben (sonst gingen bei einem Abbruch Änderungen verloren).
    $script:NvdBulkOk = $false; $script:NvdBulkSync = $null; $script:NvdLastSync = $null; $script:NvdLastFull = $null
    if (Test-Path $NvdSyncFile) {
        try {
            $sj = Get-Content $NvdSyncFile -Raw | ConvertFrom-Json
            $dts = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
            if ($sj.lastSync) { $script:NvdLastSync = [datetime]::Parse([string]$sj.lastSync, [Globalization.CultureInfo]::InvariantCulture, $dts) }
            if ($sj.lastFull) { $script:NvdLastFull = [datetime]::Parse([string]$sj.lastFull, [Globalization.CultureInfo]::InvariantCulture, $dts) }
        } catch { $script:NvdLastSync = $null; $script:NvdLastFull = $null }
    }
    function Sync-NvdKevBulk {
        $nowUtc = [datetime]::UtcNow
        $haveBulk = $false
        foreach ($v in $script:NvdCacheData.Values) { if ($v.b) { $haveBulk = $true; break } }
        $incr = ($haveBulk -and $script:NvdLastSync -and $script:NvdLastFull -and
                 $script:NvdLastSync -le $nowUtc -and ($nowUtc - $script:NvdLastSync).TotalDays -lt 119 -and
                 ($nowUtc - $script:NvdLastFull).TotalDays -lt $NvdBulkFullDays)
        $inv = [Globalization.CultureInfo]::InvariantCulture; $fmt = 'yyyy-MM-ddTHH:mm:ss.fff'
        $q = 'hasKev'
        if ($incr) {   # 15 Minuten Überlappung gegen Uhr-/Verarbeitungsversatz
            $q += ('&lastModStartDate=' + $script:NvdLastSync.AddMinutes(-15).ToString($fmt, $inv) + '%2B00:00' +
                   '&lastModEndDate='   + $nowUtc.ToString($fmt, $inv) + '%2B00:00')
        }
        $base = "https://services.nvd.nist.gov/rest/json/cves/2.0?$q&resultsPerPage=$NvdBulkPageSize"
        $headers = @{}; if ($NvdApiKey) { $headers['apiKey'] = $NvdApiKey }
        if ($incr) {
            Emit 'nvd' ((G "    NVD-Sammelabruf: nur Änderungen seit {0:yyyy-MM-dd HH:mm} UTC ..." "    NVD bulk sync: changes since {0:yyyy-MM-dd HH:mm} UTC only ...") -f $script:NvdLastSync) 'DarkGray'
        } else {
            Emit 'nvd' (G "    NVD-Sammelabruf: lade die NVD-Daten aller KEV-CVEs (einige MB, wenige Anfragen) ..." "    NVD bulk sync: downloading the NVD data of all KEV CVEs (a few MB, few requests) ...") 'DarkGray'
        }
        $today = (Get-Date).ToString('yyyy-MM-dd'); $start = 0; $total = -1; $got = 0
        $mode = if ($incr) { 'incr' } else { 'full' }
        if ($StatusFile) { try { "nvdbulk`t0|0|$mode" | Out-File -FilePath $StatusFile -Append -Encoding UTF8 } catch {} }
        while ($total -lt 0 -or $start -lt $total) {
            $resp = $null
            for ($attempt = 1; $attempt -le $NvdMaxAttempts; $attempt++) {
                try {
                    if ($start -gt 0 -and $attempt -eq 1) { Start-Sleep -Milliseconds $script:NvdDelayMs }   # Rate-Limit zwischen den Seiten
                    $resp = Invoke-RestMethod -Uri "$base&startIndex=$start" -Headers $headers -TimeoutSec 180
                    break
                } catch {
                    $code = 0; try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch {}
                    if (-not $script:NvdFirstErr) { $script:NvdFirstErr = "$($_.Exception.Message)"; $script:NvdFirstErrCode = $code }
                    if (($code -in @(400, 404)) -or ($attempt -ge $NvdMaxAttempts)) {
                        $why = if ($code -gt 0) { "HTTP $code" } else { (G 'keine Antwort/Zeitüberschreitung' 'no answer/timeout') }
                        Emit 'nvd' ((G "    NVD-Sammelabruf fehlgeschlagen ({0}) - weiter mit Einzelabfragen." "    NVD bulk sync failed ({0}) - continuing with individual requests.") -f $why) 'DarkYellow'
                        return $false
                    }
                    $wait = [Math]::Min(60, [int]($script:NvdRetryBaseSec * [Math]::Pow(2, $attempt-1)))
                    Start-Sleep -Seconds $wait
                }
            }
            if ($null -eq $resp) { return $false }
            $total = [int]$resp.totalResults
            $page = @($resp.vulnerabilities)
            foreach ($vv in $page) {
                $id = [string]$vv.cve.id
                if (-not $id) { continue }
                $pc = ConvertFrom-NvdCve $vv.cve
                $script:NvdCacheData[$id] = @{ f = $today; c = @($pc.C); s = $pc.S; sv = $pc.Sv; sver = $pc.Sver; b = 1 }
                [void]$script:NvdExpanded.Remove($id)
                $got++
            }
            if ($page.Count -eq 0) { break }
            $start += $page.Count
            if ($StatusFile) { try { "nvdbulk`t$([Math]::Min($start, $total))|$total|$mode" | Out-File -FilePath $StatusFile -Append -Encoding UTF8 } catch {} }
            if ($total -gt $NvdBulkPageSize) { Emit 'nvd' ((G "    NVD-Sammelabruf: {0}/{1}" "    NVD bulk sync: {0}/{1}") -f [Math]::Min($start, $total), $total) 'DarkGray' }
        }
        if (-not $incr -and $got -eq 0) {   # Vollabruf ohne einen einzigen Eintrag ist unplausibel -> nicht als Erfolg werten
            Emit 'nvd' (G "    NVD-Sammelabruf lieferte keine Daten - weiter mit Einzelabfragen." "    NVD bulk sync returned no data - continuing with individual requests.") 'DarkYellow'
            return $false
        }
        $script:NvdBulkSync = @{ lastSync = $nowUtc.ToString('o'); lastFull = $(if ($incr) { $script:NvdLastFull.ToString('o') } else { $nowUtc.ToString('o') }) }
        Emit 'nvd' ((G "    NVD-Sammelabruf: {0} CVEs {1}." "    NVD bulk sync: {0} CVEs {1}.") -f $got, $(if ($incr) { (G 'aktualisiert' 'updated') } else { (G 'geladen' 'loaded') })) 'DarkGray'
        return $true
    }
    $script:NvdFirstErr = ''; $script:NvdFirstErrCode = 0
    if ($NvdBulk -and -not $UseCache) { $script:NvdBulkOk = [bool](Sync-NvdKevBulk) }

    function Test-NvdCacheUsable([string]$cve) {
        if (-not $script:NvdCacheData.ContainsKey($cve)) { return $false }
        $e0 = $script:NvdCacheData[$cve]
        if ($e0.b) {
            if ($script:NvdBulkOk) { return $true }                                   # in diesem Lauf per Sammelabruf abgeglichen
            if ($UseCache -and $script:NvdLastSync -and (([datetime]::UtcNow - $script:NvdLastSync).TotalDays -lt $NvdCacheTtlDays)) { return $true }
        }
        if (-not ($UseCache -or $script:NvdStaleOk.Contains($cve))) { return $false }
        $e = $script:NvdCacheData[$cve]
        try { return [bool]($e.f -and (((Get-Date) - [datetime]$e.f).TotalDays -lt $NvdCacheTtlDays)) } catch { return [bool]$UseCache }
    }

    function Get-NvdConfig([string]$cve) {
        # 1) schon in diesem Lauf geholt? -> immer wiederverwenden (kein Doppel-Request)
        if ($script:NvdCacheData.ContainsKey($cve) -and $script:NvdFresh.Contains($cve)) {
            return (Get-NvdCacheRanges $cve)
        }
        # 2) Disk-Cache (frisch genug): mit -UseCache immer, sonst nur für länger bekannte KEV-CVEs (Standard = sonst frisch ziehen)
        if (Test-NvdCacheUsable $cve) { return (Get-NvdCacheRanges $cve) }
        if ($script:NvdFailed.Contains($cve)) { return $null }
        $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cve"
        # Bewusst KEIN eigener User-Agent: die NVD-WAF blockt Nicht-Browser-UAs gern
        # mit 403, und in PS 5.1 crasht 'User-Agent' in -Headers sogar (restricted).
        # Der PowerShell-Standard-UA funktioniert nachweislich.
        $headers = @{}; if ($NvdApiKey) { $headers['apiKey'] = $NvdApiKey }
        for ($attempt = 1; $attempt -le $NvdMaxAttempts; $attempt++) {
            try {
                if ($attempt -eq 1) { Start-Sleep -Milliseconds $script:NvdDelayMs }   # Grundabstand (Rate-Limit) nur vor dem 1. Versuch
                $resp = Invoke-RestMethod -Uri $url -Headers $headers -TimeoutSec 25
                $vl = @($resp.vulnerabilities)
                $pc = if ($vl.Count -gt 0) { ConvertFrom-NvdCve $vl[0].cve } else { [PSCustomObject]@{ C = @(); S = $null; Sv = ''; Sver = '' } }
                $script:NvdCacheData[$cve] = @{ f = (Get-Date).ToString('yyyy-MM-dd'); c = @($pc.C); s = $pc.S; sv = $pc.Sv; sver = $pc.Sver }
                [void]$script:NvdExpanded.Remove($cve)
                $arr = @(Get-NvdCacheRanges $cve)
                [void]$script:NvdFresh.Add($cve)
                $script:NvdConsecFail = 0            # Circuit-Breaker: Erfolg setzt Zähler zurück
                return $arr
            } catch {
                # HTTP-Statuscode ermitteln (PS 5.1 WebException / PS7 HttpResponseException)
                $code = 0; try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch {}
                if (-not $script:NvdFirstErr) { $script:NvdFirstErr = "$($_.Exception.Message)"; $script:NvdFirstErrCode = $code }
                if ($code -eq 404) {                 # 404 kommt bei der NVD vor allem bei ungültigem API-Key oder Störung (unbekannte CVE = 200 mit 0 Treffern):
                    [void]$script:NvdFailed.Add($cve); $script:NvdConsecFail++   # als Fehler werten, NICHT cachen (sonst 30 Tage falsches "keine Daten"), kein Retry
                    return $null
                }
                if ($attempt -lt $NvdMaxAttempts) {  # 403/429/503/Timeout -> Backoff und erneut versuchen
                    $wait = [Math]::Min(60, [int]($script:NvdRetryBaseSec * [Math]::Pow(2, $attempt-1)))
                    $why  = if ($code -gt 0) { "HTTP $code" } else { (G 'keine Antwort/Zeitüberschreitung' 'no answer/timeout') }
                    Emit 'nvd' ((G "    NVD: {0} - Versuch {1}/{2} ohne Erfolg ({3}), neuer Versuch in {4} s ..." "    NVD: {0} - attempt {1}/{2} failed ({3}), retrying in {4} s ...") -f $cve, $attempt, $NvdMaxAttempts, $why, $wait) 'DarkYellow'
                    Start-Sleep -Seconds $wait
                    continue
                }
                [void]$script:NvdFailed.Add($cve); $script:NvdConsecFail++; return $null
            }
        }
    }

    # eindeutige CVEs sammeln (nur Produkte mit vergleichbarer Version), Obergrenze beachten
    $cvesToQuery = New-Object System.Collections.Generic.HashSet[string]
    $ordered = @($matchedArr | Where-Object { -not $_.IsOs }) + @($matchedArr | Where-Object { $_.IsOs })     # Betriebssystem zuletzt
    foreach ($m in $ordered) {
        if (@(ConvertTo-VerArray $m.Version).Count -eq 0) { continue }
        if ($m.C2R) { continue }        # Click-to-Run-Office: kein NVD-Versionsvergleich möglich
        foreach ($h in $m.Hits) { [void]$cvesToQuery.Add($h.CVE) }
    }
    # Die Obergrenze zählt nur echte NVD-Abfragen; Treffer aus dem Cache sind kostenlos
    $nq = Get-NvdQueue @($cvesToQuery) { param($c) Test-NvdCacheUsable $c } $NvdMaxCves
    $queryList = @($nq.Queue); $script:NvdSkippedCves = @($nq.Skipped)
    if ($script:NvdSkippedCves.Count -gt 0) {
        Emit 'nvd' ((G "    ACHTUNG: {0} CVEs werden in diesem Lauf NICHT gegen die NVD geprüft (Limit von {1} neuen Abfragen erreicht). Bitte den Scan danach erneut ausführen (bereits geprüfte CVEs sind dann im Cache) oder ohne Limit scannen (-NoNvdLimit)." "    WARNING: {0} CVEs are NOT checked against the NVD in this run (limit of {1} new requests reached). Please run the scan again afterwards (CVEs already checked are then cached) or scan without the limit (-NoNvdLimit).") -f $script:NvdSkippedCves.Count, $NvdMaxCves) 'DarkYellow'
    }
    $qLookup = @{}; foreach ($c in $queryList) { $qLookup[$c] = $true }

    if ($queryList.Count -eq 0) {
        Emit 'nvd' (G "    Kein gematchtes Produkt mit vergleichbarer Versionsnummer - Versionsabgleich übersprungen." "    No matched product with a comparable version number - version check skipped.") 'DarkYellow'
    } else {
        $cachedFresh = @($queryList | Where-Object { Test-NvdCacheUsable $_ }).Count
        $toFetch  = $queryList.Count - $cachedFresh
        $etaTotal = [int]($toFetch * $script:NvdDelayMs / 1000)
        Emit 'nvd' ((G "    {0} CVEs zu prüfen ({1} aus dem Cache, {2} frisch). Geschätzte Dauer: {3}{4}." "    {0} CVEs to check ({1} from cache, {2} fresh). Estimated duration: {3}{4}.") -f $queryList.Count, $cachedFresh, $toFetch, (Format-Eta $etaTotal), $(if (-not $UseCache -and $toFetch -gt 5) { (G ' (mit -UseCache wäre es schneller)' ' (faster with -UseCache)') } else { '' })) 'DarkGray'
        if (-not $NvdApiKey -and $toFetch -gt 5) {
            Emit 'nvd' (G '    Hinweis: Ohne API-Key erlaubt die NVD nur ca. 5 Anfragen pro 30 s. Die Wartezeit ist normal, der Scan hängt nicht. Mit einem kostenlosen NVD-API-Key geht es ca. 10x schneller.' '    Note: without an API key the NVD only allows about 5 requests per 30 s. The waiting time is normal, the scan is not hanging. With a free NVD API key it is about 10x faster.') 'DarkGray'
        }
        $script:NvdConsecFail = 0; $done = 0; $aborted = $false
        # Restzeit nur aus den noch ausstehenden ECHTEN Abfragen schätzen (Cache-Treffer kosten keine Zeit)
        $needFetchArr = @($queryList | ForEach-Object { -not (Test-NvdCacheUsable $_) })
        $freshTotal = @($needFetchArr | Where-Object { $_ }).Count; $freshDone = 0
        $nvdSw = [System.Diagnostics.Stopwatch]::StartNew(); $lastBeat = -99.0
        foreach ($c in $queryList) {
            $isFresh = [bool]$needFetchArr[$done]
            $null = Get-NvdConfig $c; $done++; if ($isFresh) { $freshDone++ }
            # Lebenszeichen: spätestens alle ~5 s eine Meldung (ohne Key also nach jedem CVE) mit Restzeit-Schätzung
            $el = $nvdSw.Elapsed.TotalSeconds
            if (($el - $lastBeat) -ge 5 -or $done -eq $queryList.Count) {
                $lastBeat = $el
                $etaLeft = if ($freshDone -ge 2 -and $freshDone -lt $freshTotal) { [int](($el / $freshDone) * ($freshTotal - $freshDone)) } else { 0 }
                $etaTxt  = if ($done -ge $queryList.Count) { (G ' - fertig' ' - done') } elseif ($freshDone -lt 2 -and $freshTotal -gt $freshDone -and $freshTotal -ge 2) { (G ' - Restzeit wird berechnet' ' - calculating remaining time') } elseif ($etaLeft -lt 5) { (G ' - gleich fertig' ' - almost done') } else { (G " - noch ca. $(Format-Eta $etaLeft)" " - about $(Format-Eta $etaLeft) left") }
                Emit 'nvd' ((G "    NVD: {0}/{1} CVEs geprüft ({2}){3}" "    NVD: {0}/{1} CVEs checked ({2}){3}") -f $done, $queryList.Count, $c, $etaTxt) 'DarkGray'
                if ($StatusFile) { try { "nvdprog`t$done|$($queryList.Count)|$etaLeft" | Out-File -FilePath $StatusFile -Append -Encoding UTF8 } catch {} }
            }
            if ($script:NvdConsecFail -ge $NvdCircuitBreak) {   # NVD blockt/hängt -> nicht sinnlos weiterhämmern
                $aborted = $true
                Emit 'nvd' (G "[!] NVD antwortet wiederholt mit Fehlern - Versionsabgleich nach $done/$($queryList.Count) abgebrochen. Bereits geholte CVEs sind gecacht; später erneut ausführen füllt den Cache auf." "[!] NVD repeatedly answers with errors - version check aborted after $done/$($queryList.Count). CVEs already fetched are cached; running again later fills the cache.") 'Red'
                if ($script:NvdFirstErrCode -eq 404 -and $NvdApiKey) {
                    Emit 'nvd' (G "    Die NVD antwortet mit HTTP 404 - das deutet meist auf einen ungültigen API-Key hin. Bitte den Key prüfen oder ohne Key scannen." "    The NVD answers with HTTP 404 - this usually indicates an invalid API key. Please check the key or scan without a key.") 'Red'
                }
                break
            }
        }
        $answered = @($queryList | Where-Object { $script:NvdCacheData.ContainsKey($_) }).Count
        $failedN  = @($queryList | Where-Object { $script:NvdFailed.Contains($_) }).Count
        $NvdReachable = ($answered -gt 0)
        Emit 'nvd' ((G "    NVD-Daten: {0}/{1} beantwortet, {2} ohne Antwort{3}." "    NVD data: {0}/{1} answered, {2} without answer{3}.") -f $answered, $queryList.Count, $failedN, $(if($aborted){(G ' (abgebrochen)' ' (aborted)')}else{''})) $(if($NvdReachable){'DarkGray'}else{'Red'})
        if (-not $NvdReachable) {
            Emit 'nvd' (G "[!] NVD nicht erreichbar. NVD 2.0 ist bekannt für 403/503 unter Last." "[!] NVD unreachable. NVD 2.0 is known for 403/503 under load.") 'Red'
            if ($script:NvdFirstErr) { Emit 'nvd' ((G "    Erster Fehler: HTTP {0} | {1}" "    First error: HTTP {0} | {1}") -f $script:NvdFirstErrCode, $script:NvdFirstErr) 'Yellow' }
            Emit 'nvd' (G "    Tipps: (1) kostenlosen NVD-API-Key nutzen (-NvdApiKey), (2) später/außerhalb der US-Hauptzeiten erneut laufen lassen - der Cache füllt sich über mehrere Läufe." "    Tips: (1) use a free NVD API key (-NvdApiKey), (2) run again later/outside US peak hours - the cache fills up over several runs.") 'DarkYellow'
        }
    }

    # Verdikt je Treffer
    $script:OsKeySeen = $false
    $rNotQueried = L 'Diese CVE wurde in diesem Lauf nicht abgefragt (Obergrenze pro Lauf erreicht).' 'This CVE was not queried in this run (per-run limit reached).'
    $rNoAnswer   = L 'Die NVD hat für diese CVE nicht geantwortet (später erneut versuchen).' 'The NVD did not answer for this CVE (try again later).'
    foreach ($m in $matchedArr) {
        $verParsable = (@(ConvertTo-VerArray $m.Version).Count -gt 0)
        $prodAffected = $false
        foreach ($h in $m.Hits) {
            $verdict = 'Unklar'; $reason = ''
            $rangeTx = New-Object System.Collections.Generic.List[string]   # alle von der NVD genannten verwundbaren Bereiche (passendes Produkt)
            $hitTx   = New-Object System.Collections.Generic.List[string]   # davon: Bereiche, in denen die installierte Version liegt
            $fixAll  = New-Object System.Collections.Generic.List[string]; $fixHit = New-Object System.Collections.Generic.List[string]
            if ($m.IsOs) {
                # Windows selbst: Build gegen die NVD-Bereiche des eigenen Releases (windows_11_24h2 ...) vergleichen
                $osClass = 'NoData'
                if ($qLookup.ContainsKey($h.CVE)) {
                    $cfgO = Get-NvdConfig $h.CVE
                    if (@($cfgO | Where-Object { $_.Product -eq $m.OsKey }).Count -gt 0) { $script:OsKeySeen = $true }
                    $ov = Test-OsCpeVerdict $m.Version $m.OsKey $cfgO ($script:NvdCacheData.ContainsKey($h.CVE))
                    $verdict = $ov.Verdict; $reason = $ov.Reason; $osClass = $ov.Class
                    foreach ($x in $ov.Ranges)  { $rangeTx.Add($x) }
                    foreach ($x in $ov.Matched) { $hitTx.Add($x) }
                    foreach ($x in $ov.Fixed)   { $fixHit.Add($x) }
                } else { $reason = $rNotQueried }
                $h | Add-Member -NotePropertyName OsClass -NotePropertyValue $osClass -Force
            } elseif ($m.C2R) {
                $reason = L 'Click-to-Run-Installation: Die Versionsgrenzen der NVD stammen von MSI-Installationen und sind mit Click-to-Run-Builds nicht vergleichbar. Build und Update-Kanal anhand der Microsoft-Sicherheitsmitteilung zu dieser CVE prüfen.' 'Click-to-Run installation: the NVD version boundaries come from MSI installations and are not comparable with Click-to-Run builds. Check build and update channel against the Microsoft security advisory for this CVE.'
            } elseif ($m.ChromiumBase -and $verParsable -and $qLookup.ContainsKey($h.CVE)) {
                # Chromium-basiert (Edge): eigene CPE-Bereiche, sonst abgeleitet aus dem Chrome-Fix
                $cfgC = Get-NvdConfig $h.CVE
                if (-not $cfgC -and ($script:NvdFailed.Contains($h.CVE) -or -not $script:NvdCacheData.ContainsKey($h.CVE))) { $reason = $rNoAnswer }
                else {
                    $cv = Test-ChromiumBaseVerdict $m.Version $m.CpeProducts $cfgC $h.CVE
                    $verdict = $cv.Verdict; $reason = $cv.Reason
                    foreach ($x in $cv.Ranges)  { $rangeTx.Add($x) }
                    foreach ($x in $cv.Matched) { $hitTx.Add($x) }
                    foreach ($x in $cv.Fixed)   { $fixHit.Add($x) }
                }
            } elseif ($verParsable -and $qLookup.ContainsKey($h.CVE)) {
                $cfg = Get-NvdConfig $h.CVE
                if (-not $cfg) {
                    if ($script:NvdFailed.Contains($h.CVE) -or -not $script:NvdCacheData.ContainsKey($h.CVE)) { $reason = $rNoAnswer }
                    else { $reason = L 'Die NVD nennt für diese CVE keine Versionsangaben (z. B. noch nicht analysiert).' 'The NVD gives no version information for this CVE (e.g. not analyzed yet).' }
                } else {
                    $av = Test-AppVerdict $m.Version $m.Tokens $cfg
                    $verdict = $av.Verdict; $reason = $av.Reason
                    foreach ($x in $av.Ranges)  { $rangeTx.Add($x) }
                    foreach ($x in $av.Matched) { $hitTx.Add($x) }
                    foreach ($x in $av.Fixed)   { $fixHit.Add($x) }
                }
            } elseif (-not $verParsable) { $verdict = 'keine Version'; $reason = L 'Die Versionsnummer im Inventar ist nicht auswertbar (leer oder ohne Zahlen).' 'The version number in the inventory cannot be evaluated (empty or without digits).' }
            else { $reason = $rNotQueried }
            $fixSel = if ($fixHit.Count -gt 0) { $fixHit } else { $fixAll }
            $h | Add-Member -NotePropertyName VerdictReason  -NotePropertyValue $reason -Force
            $h | Add-Member -NotePropertyName AffectedRanges -NotePropertyValue ([string[]]$rangeTx.ToArray()) -Force
            $h | Add-Member -NotePropertyName MatchedRanges  -NotePropertyValue ([string[]]$hitTx.ToArray()) -Force
            $h | Add-Member -NotePropertyName FixedIn        -NotePropertyValue ([string[]]@($fixSel | Select-Object -First 3)) -Force
            $h | Add-Member -NotePropertyName VersionVerdict -NotePropertyValue $verdict -Force
            $ce = $script:NvdCacheData[$h.CVE]
            if ($ce -and $null -ne $ce.s -and "$($ce.s)" -ne '') {
                $h | Add-Member -NotePropertyName CvssScore    -NotePropertyValue ([double]$ce.s) -Force
                $h | Add-Member -NotePropertyName CvssSeverity -NotePropertyValue "$($ce.sv)"     -Force
                $h | Add-Member -NotePropertyName CvssVersion  -NotePropertyValue "$($ce.sver)"   -Force
            }
            if ($verdict -eq 'Betroffen') { $affectedCount++; $prodAffected = $true }
        }
        if ($m.IsOs) {
            # Nur Treffer behalten, die für DIESES Windows eine Aussage haben; "betrifft andere Releases" und "keine NVD-Antwort" nur zählen
            $tally = @{ Affected = 0; Patched = 0; NotListed = 0; Unbounded = 0; NoCpe = 0; NoData = 0; KeyUnknown = 0 }
            $keepOs = New-Object System.Collections.Generic.List[object]
            foreach ($h in $m.Hits) {
                $cl = if ($h.OsClass) { [string]$h.OsClass } else { 'NoData' }
                $tally[$cl]++
                if ($cl -ne 'NotListed' -and $cl -ne 'NoData') { $keepOs.Add($h) }
            }
            $m.Hits.Clear(); foreach ($h in $keepOs) { $m.Hits.Add($h) }
            # Nennt die NVD das eigene Release bei KEINER abgefragten CVE, ist es dort vermutlich (noch) nicht erfasst:
            # "betrifft nur andere Releases" wäre dann eine falsche Entwarnung -> als nicht prüfbar zählen.
            if (-not $script:OsKeySeen -and $tally.NotListed -gt 0) { $tally.KeyUnknown = $tally.NotListed; $tally.NotListed = 0 }
            $script:OsCheck.Tally = $tally
        }
        $m | Add-Member -NotePropertyName Affected -NotePropertyValue $prodAffected -Force
    }
    # Windows-Eintrag ohne verbleibende Treffer entfällt (steht nur noch als Zusammenfassung in "Aussagekraft dieses Scans")
    $matchedArr = @($matchedArr | Where-Object { -not ($_.IsOs -and $_.Hits.Count -eq 0) })
    $totalCVEs = ($matchedArr | ForEach-Object { $_.Hits.Count } | Measure-Object -Sum).Sum
    $affectedProducts = @($matchedArr | Where-Object Affected).Count

    # Cache zurückschreiben (mit Zeitstempel je CVE)
    $cacheSaved = $false
    try { $script:NvdCacheData | ConvertTo-Json -Depth 6 -Compress | Out-File $NvdCache -Encoding UTF8; $cacheSaved = $true } catch {}
    # Sync-Stand nur schreiben, wenn der Cache wirklich gespeichert ist (sonst würde der nächste Lauf Änderungen überspringen)
    if ($cacheSaved -and $script:NvdBulkSync) { try { $script:NvdBulkSync | ConvertTo-Json -Compress | Out-File $NvdSyncFile -Encoding UTF8 } catch {} }
    Write-Host ((G "    Versionsabgleich: {0} Treffer konkret betroffen, {1} Produkte." "    Version check: {0} hits confirmed affected, {1} products.") -f $affectedCount, $affectedProducts) -ForegroundColor $(if($affectedCount){'Red'}else{'Green'})
} else {
    foreach ($m in $matchedArr) { foreach ($h in $m.Hits) { $h | Add-Member -NotePropertyName VersionVerdict -NotePropertyValue 'nicht geprüft' -Force }; $m | Add-Member -NotePropertyName Affected -NotePropertyValue $false -Force }
}

#endregion

#region ===================== EXPORT MATCHES (JSON) ==========================

# Matches als JSON sichern
$matchedArr | ForEach-Object {
    [PSCustomObject]@{ Product=$_.Name; Version=$_.Version; Source=$_.Source; RansomwareRelated=$_.HasRansom; Affected=$_.Affected; Hits=$_.Hits }
} | ConvertTo-Json -Depth 6 | Out-File $MatchPath -Encoding UTF8

Write-Host ((G "    {0} Produkte mit KEV-Bezug, {1} CVE-Treffer gesamt." "    {0} products with KEV relevance, {1} CVE hits in total.") -f $matchedArr.Count, ([int]$totalCVEs)) -ForegroundColor $(if($matchedArr.Count){'Yellow'}else{'Green'})

#endregion

#region ===================== DIFF ZUM LETZTEN LAUF ==========================
# Vergleicht die aktuellen Treffer (Produkt|CVE) mit dem letzten Lauf: was ist NEU,
# was ist WEG (gepatcht/deinstalliert). Passt zum Frisch-als-Standard-Modell:
# der eigentliche Alltagswert ist "was kam heute dazu".
$newHits = 0; $resolvedHits = 0; $prevDate = ''
$prevKeys = @{}
if (-not $NoKev -and $kev) {      # ohne geladenen KEV-Katalog den gespeicherten Stand NICHT überschreiben (sonst geht die Historie verloren)
    if (Test-Path $StatePath) {
        try {
            $prev = Get-Content $StatePath -Raw | ConvertFrom-Json
            $prevDate = "$($prev.date)"
            foreach ($k in $prev.keys) { $prevKeys["$k"] = $true }
        } catch {}
    }
    $curKeys = @{}
    foreach ($m in $matchedArr) {
        foreach ($h in $m.Hits) {
            $key = "$($m.Name)|$($h.CVE)"
            $curKeys[$key] = $true
            $isNew = ($prevKeys.Count -gt 0 -and -not $prevKeys.ContainsKey($key))
            $h | Add-Member -NotePropertyName IsNew -NotePropertyValue $isNew -Force
            if ($isNew) { $newHits++ }
        }
        $m | Add-Member -NotePropertyName HasNew -NotePropertyValue ([bool](@($m.Hits | Where-Object IsNew).Count)) -Force
    }
    if ($prevKeys.Count -gt 0) {
        foreach ($k in $prevKeys.Keys) { if (-not $curKeys.ContainsKey($k)) { $resolvedHits++ } }
    }
    # aktuellen Stand speichern (für den nächsten Lauf)
    try {
        [PSCustomObject]@{ date = (Get-Date).ToString('yyyy-MM-dd HH:mm'); keys = @($curKeys.Keys) } |
            ConvertTo-Json -Depth 3 | Out-File $StatePath -Encoding UTF8
    } catch {}
    if ($prevKeys.Count -gt 0) {
        Write-Host ((G "    Diff zum letzten Lauf ({0}): {1} neu, {2} nicht mehr vorhanden." "    Diff to the last run ({0}): {1} new, {2} no longer present.") -f $prevDate, $newHits, $resolvedHits) -ForegroundColor $(if($newHits){'Yellow'}else{'DarkGray'})
    } else {
        Write-Host (G "    Erster erfasster Lauf - ab dem nächsten Mal wird 'neu seit letztem Lauf' angezeigt." "    First recorded run - from next time on 'new since last run' will be shown.") -ForegroundColor DarkGray
    }
} else {
    foreach ($m in $matchedArr) { foreach ($h in $m.Hits) { $h | Add-Member -NotePropertyName IsNew -NotePropertyValue $false -Force }; $m | Add-Member -NotePropertyName HasNew -NotePropertyValue $false -Force }
}

#endregion

#region ============================ HTML-REPORT ============================

Emit 'report' (G "[*] Erzeuge HTML-Report ..." "[*] Creating HTML report ...")
$now = Get-Date -Format 'dd.MM.yyyy HH:mm:ss'; $nowEn = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$sb  = New-Object System.Text.StringBuilder

function Conf-Class($c) { switch ($c) { 'Hoch'{'c-high'} 'Mittel'{'c-med'} default{'c-low'} } }
# Anzeige interner (deutscher) Schlüsselwerte in beiden Sprachen
$script:VerdictEn = @{ 'Betroffen' = 'Affected'; 'Vermutlich gepatcht' = 'Probably patched'; 'Unklar' = 'Unclear'; 'keine Version' = 'No version'; 'nicht geprüft' = 'Not checked' }
$script:ConfEn    = @{ 'Hoch' = 'High'; 'Mittel' = 'Medium'; 'Niedrig' = 'Low' }
$script:BasisEn   = @{ 'Produkt + Hersteller' = 'Product + vendor'; 'Produktname' = 'Product name'; 'Betriebssystem (Build)' = 'Operating system (build)' }
$script:SourceEn  = @{ 'Betriebssystem' = 'Operating system' }
function Bmap($v, $map) { $t = "$v"; if ($map.ContainsKey($t)) { B $t $map[$t] } else { Enc $t } }
function Rg-En([string]$t) { ((($t -replace ' und ', ' and ') -replace '^alle Versionen$', 'all versions') -replace '(^|Chromium )ab ', '$1from ') -replace '^neuer als ', 'newer than ' }
function Rg($t) { B "$t" (Rg-En "$t") }

# --- KEV-Match-Sektion ---
$matchHtml = New-Object System.Text.StringBuilder
if ($VersionResolved -and -not $NvdReachable -and $matchedArr.Count -gt 0) {
    [void]$matchHtml.Append("<div class='nvdwarn'>$(B 'Der NVD-Versionsabgleich war bei diesem Lauf nicht erreichbar (NVD 2.0 antwortet unter Last oft mit 403/503). Die Versions-Verdikte stehen daher auf „Unklar“. Mit NVD-API-Key oder einem erneuten Lauf (der Cache füllt sich schrittweise) wird das aufgelöst.' 'The NVD version check was unreachable in this run (NVD 2.0 often answers with 403/503 under load). The version verdicts are therefore "Unclear". An NVD API key or another run (the cache fills up step by step) resolves this.')</div>")
}
if ($KevSkipped) {
    [void]$matchHtml.Append("<div class='nvdwarn'>$(B 'KEV-Abgleich wurde übersprungen (-NoKev / GUI-Option). Dieser Report zeigt nur Geräte-Inventar und Sicherheits-Posture, keinen Schwachstellen-Abgleich.' 'KEV matching was skipped (-NoKev / GUI option). This report only shows the device inventory and security posture, no vulnerability matching.')</div>")
} elseif ($matchedArr.Count -eq 0) {
    [void]$matchHtml.Append("<div class='ok-banner'>$(B 'Keine installierten Produkte im KEV-Katalog gefunden. Trotzdem: Updates aktuell halten.' 'No installed products found in the KEV catalog. Still: keep updates current.')</div>")
} else {
    # Frist (CISA dueDate) je Treffer auswerten + Produkt-Flags für die Dringlichkeit
    foreach ($m in $matchedArr) {
        $maxF = 0; $overdue = $false
        foreach ($h in $m.Hits) {
            $fi = Get-FristInfo $h.Due
            $h | Add-Member -NotePropertyName FristRank  -NotePropertyValue $fi.Rank  -Force
            $h | Add-Member -NotePropertyName FristLabel -NotePropertyValue $fi.Label -Force
            $h | Add-Member -NotePropertyName FristClass -NotePropertyValue $fi.Class -Force
            $vr = switch ($h.VersionVerdict) { 'Betroffen' {3} 'Unklar' {2} 'nicht geprüft' {2} 'keine Version' {2} default {1} }
            $h | Add-Member -NotePropertyName VerdictRank -NotePropertyValue $vr -Force
            # Bereits per NVD als "Vermutlich gepatcht" eingestufte Treffer sind kein Dringlichkeitsgrund (auch nicht mit alter Frist)
            $openHit = ($h.VersionVerdict -ne 'Vermutlich gepatcht')
            if ($openHit -and $fi.Rank -gt $maxF) { $maxF = $fi.Rank }
            if ($openHit -and $fi.Rank -eq 3) { $overdue = $true }
        }
        $m | Add-Member -NotePropertyName MaxFrist   -NotePropertyValue $maxF    -Force
        $m | Add-Member -NotePropertyName HasOverdue -NotePropertyValue $overdue -Force
        $m | Add-Member -NotePropertyName HasRansom  -NotePropertyValue ([bool]($m.Hits | Where-Object { $_.Ransom -and $_.VersionVerdict -ne 'Vermutlich gepatcht' })) -Force
    }
    $ransomProducts = @($matchedArr | Where-Object HasRansom).Count

    # Dringlichkeits-Reihenfolge der Produkte: Ransomware -> Frist -> betroffene Version -> Konfidenz/Anzahl
    $matchedArr = @($matchedArr | Sort-Object @{E={$_.HasRansom};D=$true}, @{E={$_.MaxFrist};D=$true}, @{E={$_.Affected};D=$true}, @{E={$_.BestRank};D=$true}, @{E={$_.Hits.Count};D=$true}, Name)

    if ($newHits -gt 0) {
        $resDe = if ($resolvedHits -gt 0) { " $resolvedHits Treffer sind nicht mehr vorhanden (gepatcht/entfernt)." } else { '' }
        $resEn = if ($resolvedHits -gt 0) { " $resolvedHits hits are no longer present (patched/removed)." } else { '' }
        [void]$matchHtml.Append("<div class='newbanner'>$(BH "<b>$newHits neue Treffer</b> seit dem letzten Lauf ($(Enc $prevDate)) - unten mit <span class='neu'>NEU</span> markiert.$(Enc $resDe)" "<b>$newHits new hits</b> since the last run ($(Enc $prevDate)) - marked <span class='neu'>NEW</span> below.$(Enc $resEn)")</div>")
    }

    foreach ($m in $matchedArr) {
        $ransomPill = if ($m.HasRansom)   { PillK 'pill ransom' (B 'Ransomware-Bezug' 'Ransomware use') 'Ransomware' } else { '' }
        $overduePill= if ($m.HasOverdue)  { PillK 'pill vbad' (B 'Frist überfällig' 'Overdue') 'Frist' } else { '' }
        $newPill    = if ($m.HasNew)      { PillK 'pill neu' (B 'NEU' 'NEW') 'NEU' } else { '' }
        $confLabel  = switch ($m.BestRank) { 3 {'Hoch'} 2 {'Mittel'} default {'Niedrig'} }
        $verPill = ''
        if ($VersionResolved) {
            if ($m.Affected) { $verPill = PillK 'pill vbad' (B 'Version betroffen' 'Version affected') 'V_Betroffen' }
            elseif (@($m.Hits | Where-Object { $_.VersionVerdict -eq 'Vermutlich gepatcht' }).Count -gt 0) { $verPill = PillK 'pill vok' (B 'Vermutlich gepatcht' 'Probably patched') 'V_Gepatcht' }
            else { $verPill = PillK 'pill vunk' (B 'Version unklar' 'Version unclear') 'V_Unklar' }
        }
        $openAttr = ''   # Treffer bewusst standardmäßig eingeklappt; Dringlichkeit zeigen die Pills im Kopf der Karte
        [void]$matchHtml.Append("<details class='mcard'$openAttr><summary class='mhead'><div class='mname'>$(Enc $m.Name)<span class='mver'>$(Enc $m.Version)</span></div>")
        [void]$matchHtml.Append("<div class='mmeta'>$newPill$overduePill$ransomPill$verPill<span class='pill count'>$($m.Hits.Count) CVE</span>$(PillK "conf $(Conf-Class $confLabel)" (Bmap $confLabel $script:ConfEn) 'Konfidenz')<span class='pill src'>$(Bmap $m.Source $script:SourceEn)</span></div></summary>")
        [void]$matchHtml.Append("<table class='cve'><thead><tr><th>$(TipK 'CVE' 'CVE')</th><th>$(TipK (B 'KEV-Produkt (Hersteller)' 'KEV product (vendor)') 'KEV')</th><th>$(TipK (B 'Zuordnung & Version' 'Match & version') 'Zuordnung')</th><th>$(TipK (B 'CISA-Frist' 'CISA due date') 'Frist')</th><th>$(TipK (B 'Schwachstelle & Handlungsempfehlung' 'Vulnerability & required action') 'Schwachstelle')</th></tr></thead><tbody>")
        # Treffer-Reihenfolge: Ransomware -> Frist -> Versions-Verdikt -> Konfidenz
        $sortedHits = $m.Hits | Sort-Object @{E={ $_.VersionVerdict -eq 'Vermutlich gepatcht' }}, @{E={$_.Ransom};D=$true}, @{E={$_.FristRank};D=$true}, @{E={$_.VerdictRank};D=$true}, @{E={$rank[$_.Confidence]};D=$true}, @{E={ if ($null -ne $_.CvssScore) { [double]$_.CvssScore } else { -1 } };D=$true}
        $pToggled = $false; $nPatched = @($m.Hits | Where-Object { $_.VersionVerdict -eq 'Vermutlich gepatcht' }).Count
        foreach ($h in $sortedHits) {
            # Treffer, die laut NVD für diesen Stand nicht betroffen sind, stehen eingeklappt hinter einer Schaltzeile (beim Drucken sichtbar)
            $isPatched = ($h.VersionVerdict -eq 'Vermutlich gepatcht')
            if ($isPatched -and -not $pToggled) {
                $pToggled = $true
                [void]$matchHtml.Append("<tr class='ptoggle' onclick='cwP(this)'><td colspan='5'><span class='ptxt' data-n='$nPatched'>&#9656; <span class='l-de'>$nPatched Treffer mit Verdikt &quot;Vermutlich gepatcht&quot; <span class='pt-on'>ausblenden</span><span class='pt-off'>anzeigen</span></span><span class='l-en'>$nPatched hits with verdict &quot;Probably patched&quot;: <span class='pt-on'>hide</span><span class='pt-off'>show</span></span></span></td></tr>")
            }
            $trTag = if ($isPatched) { "<tr class='phid'>" } else { '<tr>' }
            $rp = if ($h.Ransom) { ' ' + (Pill 'dot' '' $script:Tips['Ransomware']) } else { '' }
            $newB = if ($h.IsNew) { ' ' + (PillK 'neu' (B 'NEU' 'NEW') 'NEU') } else { '' }
            # Versions-Block: Installiert / Betroffen (Bereiche laut NVD, passender Bereich rot) / Behoben, darunter das Verdikt samt Begründung
            $instHtml = if ([string]::IsNullOrWhiteSpace($m.Version)) { B 'unbekannt' 'unknown' } else { Enc ([string]$m.Version) }
            $vboxHtml = "<div class='vrow'><span class='vl'>$(TipK (B 'Installiert' 'Installed') 'Installiert')</span><span class='vx mono'>$instHtml</span></div>"
            $hitR = @($h.MatchedRanges | Where-Object { $_ })
            $allR = @($h.AffectedRanges | Where-Object { $_ })
            if ($allR.Count -gt 0) {
                $ordR  = @($hitR) + @($allR | Where-Object { $hitR -notcontains $_ })     # passende Bereiche zuerst
                $shownR = @($ordR | Select-Object -First 4)
                $chips = ''
                foreach ($rt in $shownR) { $rc = if ($hitR -contains $rt) { 'rng rng-hit' } else { 'rng' }; $chips += "<span class='$rc'>$(Rg $rt)</span>" }
                if ($ordR.Count -gt $shownR.Count) { $chips += "<span class='rng-more' title='$(Enc (($ordR | ForEach-Object { Rg-En $_ }) -join ' | '))'>+$($ordR.Count - $shownR.Count) $(B 'weitere' 'more')</span>" }
                $vboxHtml += "<div class='vrow'><span class='vl'>$(TipK (B 'Betroffen' 'Affected') 'Betroffen')</span><span class='vx'>$chips</span></div>"
            }
            $fixR = @($h.FixedIn | Where-Object { $_ })
            if ($fixR.Count -gt 0) { $vboxHtml += "<div class='vrow'><span class='vl'>$(TipK (B 'Behoben' 'Fixed') 'Behoben')</span><span class='vx'>$(Rg ($fixR -join ', '))</span></div>" }
            $vvHtml = "<div class='vbox'>$vboxHtml</div>"
            if ($VersionResolved) {
                $vvClass = switch ($h.VersionVerdict) { 'Betroffen' {'vv-bad'} 'Vermutlich gepatcht' {'vv-ok'} default {'vv-unk'} }
                $whyHtml = if ("$($h.VerdictReason)") { "<div class='vwhy'>$(V $h.VerdictReason)</div>" } else { '' }
                $vkey = switch ($h.VersionVerdict) { 'Betroffen' {'V_Betroffen'} 'Vermutlich gepatcht' {'V_Gepatcht'} default {'V_Unklar'} }
                $vvHtml += "<div class='vver $vvClass'>$(TipK (Bmap $h.VersionVerdict $script:VerdictEn) $vkey)</div>$whyHtml"
            }
            $descHtml = ''   # CISA-Kurzbeschreibung aus dem KEV-Katalog (Englisch); lange Texte als Teaser mit Aufklappen
            if ($h.Desc) {
                $dt = ([string]$h.Desc).Trim()
                if ($dt.Length -gt 240) {
                    $cut = $dt.Substring(0, 200); $sp = $cut.LastIndexOf(' '); if ($sp -gt 120) { $cut = $cut.Substring(0, $sp) }
                    $cut = $cut.TrimEnd(' ', ',', ';', ':', '.')
                    $descHtml = "<details class='cdesc'><summary><span class='cd-short'>$(Enc $cut)&hellip;</span> <span class='cd-more'>$(B 'mehr' 'more')</span><span class='cd-less'>$(B 'weniger' 'less')</span></summary><div class='cd-full'>$(Enc $dt)</div></details>"
                } else { $descHtml = "<div class='cdesc'>$(Enc $dt)</div>" }
            }
            $sevHtml = ''   # CVSS-Basiswert + Schweregrad laut NVD (nur wenn die NVD für diese CVE abgefragt wurde)
            if ($null -ne $h.CvssScore) {
                $sevKey  = "$($h.CvssSeverity)".ToUpper()
                $sevLbl  = switch ($sevKey) { 'CRITICAL' {B 'Kritisch' 'Critical'} 'HIGH' {B 'Hoch' 'High'} 'MEDIUM' {B 'Mittel' 'Medium'} 'LOW' {B 'Niedrig' 'Low'} default {B 'Unbekannt' 'Unknown'} }
                $sevCls  = switch ($sevKey) { 'CRITICAL' {'cvs-crit'} 'HIGH' {'cvs-high'} 'MEDIUM' {'cvs-med'} default {'cvs-low'} }
                $scoreTx = ([double]$h.CvssScore).ToString('0.0', [System.Globalization.CultureInfo]::InvariantCulture)
                $sevHtml = "<div class='cvs $sevCls tip' tabindex='0' $(Get-TipAttr (L ("CVSS v$($h.CvssVersion) Basiswert (NVD). " + $script:Tips['CVSS'].de) ("CVSS v$($h.CvssVersion) base score (NVD). " + $script:Tips['CVSS'].en)))>CVSS $scoreTx &middot; $sevLbl</div>"
            }
            $dueCls = switch ($h.FristClass) { 'warn' {'due-warn'} 'caution' {'due-caution'} default {'muted'} }
            [void]$matchHtml.Append("$trTag<td class='mono'><a href='https://nvd.nist.gov/vuln/detail/$(Enc $h.CVE)' target='_blank' rel='noopener'>$(Enc $h.CVE)</a>$rp$newB$sevHtml</td>")
            [void]$matchHtml.Append("<td>$(Enc $h.Product) <span class='muted'>($(Enc $h.Vendor))</span></td>")
            [void]$matchHtml.Append("<td><span class='conf $(Conf-Class $h.Confidence)'>$(Bmap $h.Confidence $script:ConfEn)</span><div class='basis'>$(Bmap $h.Basis $script:BasisEn)</div>$vvHtml</td>")
            [void]$matchHtml.Append("<td class='mono $dueCls'>$(V $h.FristLabel)</td>")
            [void]$matchHtml.Append("<td class='desc'><div class='vname'>$(Enc $h.Name)</div>$descHtml<div class='action'>$(Enc $h.Action)</div></td></tr>")
        }
        [void]$matchHtml.Append('</tbody></table></details>')
    }
}

# --- Inventar-Sektion (nach Quelle, aufklappbar) ---
$invHtml = New-Object System.Text.StringBuilder
foreach ($grp in ($invClean | Group-Object Source | Sort-Object Name)) {
    [void]$invHtml.Append("<details class='invgrp' data-src='$(Enc $grp.Name)'><summary>$(Enc $grp.Name) <span class='muted'>($($grp.Count))</span></summary><table class='inv'><thead><tr><th>Name</th><th>Version</th><th>$(B 'Hersteller' 'Vendor')</th></tr></thead><tbody>")
    foreach ($i in ($grp.Group | Sort-Object Name)) {
        [void]$invHtml.Append("<tr><td>$(Enc $i.Name)</td><td class='mono muted'>$(Enc $i.Version)</td><td class='muted'>$(Enc $i.Manufacturer)</td></tr>")
    }
    [void]$invHtml.Append('</tbody></table></details>')
}
# Suchleiste (läuft komplett im Browser, kein Netzwerk): Freitext + Filter nach Quelle
$invBar = New-Object System.Text.StringBuilder
[void]$invBar.Append("<div class='invbar noprint'><input type='search' id='invq' placeholder='$(Enc (G 'Inventar durchsuchen: Name, Version oder Hersteller (mehrere Begriffe möglich) ...' 'Search inventory: name, version or vendor (several terms possible) ...'))' data-ph-de='Inventar durchsuchen: Name, Version oder Hersteller (mehrere Begriffe möglich) ...' data-ph-en='Search inventory: name, version or vendor (several terms possible) ...' oninput='cwInv()' autocomplete='off' aria-label='Search inventory'><div class='chips' id='invchips'>")
foreach ($grp in ($invClean | Group-Object Source | Sort-Object Name)) {
    [void]$invBar.Append("<label class='chip'><input type='checkbox' value='$(Enc $grp.Name)' checked onchange='cwInv()'>$(Enc $grp.Name) <span class='muted'>($($grp.Count))</span></label>")
}
[void]$invBar.Append("</div><button type='button' onclick='cwInvReset()'>$(B 'Zurücksetzen' 'Reset')</button><span id='invcount' class='muted'>$($invClean.Count)</span></div>")

# --- Sicherheits-Posture: Kacheln mit Risiko-Hervorhebung ---
function Posture-Class([string]$v) {
    if ($v -match '\(Risiko\)' -or $v -match 'JA - Neustart') { return 'v warn' }
    if ($v -cmatch '^AKTIVIERT$' -or $v -match 'inaktiv|nicht vorhanden|Mainstream endete|nicht unterstützt|unvollständig|dringend|bitte prüfen|\(Hinweis\)') { return 'v caution' }
    return 'v'
}
$postureItems = [ordered]@{
    'Neustart ausstehend' = $RebootState
    'Letztes Update'      = $PatchState
    'Uptime'              = $UptimeState
    'OS-Support'          = $OSSupport
    'Secure Boot'         = $SecureBoot
    'BitLocker (System)'  = $BitLocker
    'TPM'                 = $TPMState
    'RDP'                 = $RDPState
    'SMBv1'               = $SMB1State
    'UAC'                 = $UACState
    'Registrierte AV'     = $AVState
    'Lokale Administratoren' = $LocalAdmins
    'Gast-Konto'          = $GuestState
    'Autologon'           = $AutoLogonState
    'SMB-Freigaben'       = $SmbShares
    'LSA-Schutz (RunAsPPL)' = $LsaState
    'Virtualisierungsbasierte Sicherheit' = $VBSState
    'Speicherintegrität (HVCI)' = $HVCIState
    'Credential Guard'    = $CredGuard
    'NTLM-Kompatibilität' = $NtlmState
    'Geräte-Einbindung'   = $JoinState
    'Scan als Admin'      = $AdminState
}

# Englische Beschriftungen der Posture- und Defender-Kacheln (die deutschen Schlüssel bleiben intern unverändert)
$script:LabelEn = @{
    'Neustart ausstehend' = 'Restart pending'; 'Letztes Update' = 'Last update'; 'Uptime' = 'Uptime'; 'OS-Support' = 'OS support'
    'Secure Boot' = 'Secure Boot'; 'BitLocker (System)' = 'BitLocker (system)'; 'TPM' = 'TPM'; 'RDP' = 'RDP'; 'SMBv1' = 'SMBv1'; 'UAC' = 'UAC'
    'Registrierte AV' = 'Registered AV'; 'Lokale Administratoren' = 'Local administrators'; 'Gast-Konto' = 'Guest account'; 'Autologon' = 'Autologon'
    'SMB-Freigaben' = 'SMB shares'; 'LSA-Schutz (RunAsPPL)' = 'LSA protection (RunAsPPL)'; 'Virtualisierungsbasierte Sicherheit' = 'Virtualization-based security'
    'Speicherintegrität (HVCI)' = 'Memory integrity (HVCI)'; 'Credential Guard' = 'Credential Guard'; 'NTLM-Kompatibilität' = 'NTLM compatibility'
    'Geräte-Einbindung' = 'Device join'; 'Scan als Admin' = 'Scan as admin'
    'Produktversion' = 'Product version'; 'Engine-Version' = 'Engine version'; 'Signatur-Version' = 'Signature version'; 'Betriebsmodus' = 'Running mode'
    'Virenschutz' = 'Antivirus'; 'Echtzeitschutz' = 'Real-time protection'; 'Verhaltensüberwachung' = 'Behavior monitoring'; 'Manipulationsschutz' = 'Tamper protection'
    'Cloud-Schutz (MAPS)' = 'Cloud protection (MAPS)'; 'PUA-Schutz (unerwünschte Apps)' = 'PUA protection (unwanted apps)'; 'Netzwerkschutz' = 'Network protection'
    'Kontrollierter Ordnerzugriff' = 'Controlled folder access'; 'ASR-Regeln (Angriffsflächen-Reduzierung)' = 'ASR rules (attack surface reduction)'
    'Ausschlüsse' = 'Exclusions'; 'Letzter Quick-Scan' = 'Last quick scan'; 'Letzter Full-Scan' = 'Last full scan'; 'Microsoft Defender' = 'Microsoft Defender'
}
$postureHtml = New-Object System.Text.StringBuilder
foreach ($k in $postureItems.Keys) {
    $val = $postureItems[$k]
    [void]$postureHtml.Append("<div class='kv'><div class='k'>$(Bmap $k $script:LabelEn)</div><div class='$(Posture-Class "$val")'>$(V $val)</div></div>")
}

# --- Microsoft Defender (eigener Block) ---
$defenderHtml = New-Object System.Text.StringBuilder
foreach ($dk in $DefenderItems.Keys) {
    $dval = $DefenderItems[$dk]
    [void]$defenderHtml.Append("<div class='kv'><div class='k'>$(Bmap $dk $script:LabelEn)</div><div class='$(Posture-Class "$dval")'>$(V $dval)</div></div>")
}

# --- Massenspeicher: pro physischem Datenträger eine Karte, darin alle Volumes (dynamisch) ---
$storageHtml = New-Object System.Text.StringBuilder
if ($Storage.Count -eq 0) {
    $stErr = if ($script:StorageErrors.Count -gt 0) { ($script:StorageErrors -join ' | ') } else { '' }
    [void]$storageHtml.Append("<div class='nvdwarn'>$(B "Keine Datenträger ermittelt. $(if ($stErr) { "Grund: $stErr" })" "No disks found. $(if ($stErr) { "Reason: $stErr" })")</div>")
}
foreach ($dev in $Storage) {
    $hCls = if ($dev.Health -match '^(Healthy|OK)$') { 'vok' } elseif ($dev.Health -eq 'n/a') { 'vunk' } else { 'vbad' }
    $hTxt = switch -Regex ($dev.Health) { '^(Healthy|OK)$' { L 'Zustand: gesund' 'Health: healthy' } '^Warning$' { L 'Zustand: Warnung' 'Health: warning' } '^Unhealthy$' { L 'Zustand: fehlerhaft' 'Health: unhealthy' } '^n/a$' { L 'Zustand: unbekannt' 'Health: unknown' } default { L "Zustand: $($dev.Health)" "Health: $($dev.Health)" } }
    $pills = "<span class='pill src'>$(V $dev.Kind)</span>"
    if ($dev.Bus -and $dev.Bus -ne '-') { $pills += "<span class='pill src'>$(Enc $dev.Bus)</span>" }
    $pills += "<span class='pill $hCls'>$(V $hTxt)</span>"
    if ($null -ne $dev.Wear -and $dev.Bus -ne 'USB') { $wCls = if ([int]$dev.Wear -ge 80) { 'vbad' } else { 'vunk' }; $pills += "<span class='pill $wCls'>$(B 'Verschleiß' 'Wear') $(Enc "$($dev.Wear)") %</span>" }
    if ($null -ne $dev.TempC -and [int]$dev.TempC -gt 0) { $pills += "<span class='pill vunk'>$(Enc "$($dev.TempC)") °C</span>" }

    [void]$storageHtml.Append("<div class='disk'><div class='dhead'><div class='dname'>$(V $dev.Model)<span class='dsize'>$(Enc (Format-SizeGB $dev.SizeGB))</span></div><div class='mmeta'>$pills</div></div>")
    if ($dev.Volumes.Count -gt 0) {
        [void]$storageHtml.Append("<table class='inv'><thead><tr><th>$(B 'Laufwerk' 'Drive')</th><th>$(B 'Bezeichnung' 'Label')</th><th>$(B 'Dateisystem' 'File system')</th><th>$(B 'Belegung' 'Usage')</th><th>$(B 'Frei' 'Free')</th><th>BitLocker</th></tr></thead><tbody>")
        foreach ($vol in $dev.Volumes) {
            $barCls = if ($vol.UsedPct -ge 90) { 'hi' } elseif ($vol.UsedPct -ge 80) { 'mid' } else { '' }
            $blCls  = if ($dev.Bus -eq 'USB' -and "$($vol.BitLocker)" -match 'FullyDecrypted|Schutz Off') { 'mono due-caution' } else { 'mono muted' }
            [void]$storageHtml.Append("<tr><td class='mono'>$(Enc $vol.Laufwerk)</td><td>$(Enc $vol.Label)</td><td class='mono muted'>$(Enc $vol.FS)</td>")
            [void]$storageHtml.Append("<td><div class='bar'><span class='$barCls' style='width:$($vol.UsedPct)%'></span></div><div class='basis'>$(B ('{0} von {1} belegt ({2} %)' -f (Format-SizeGB $vol.UsedGB), (Format-SizeGB $vol.SizeGB), $vol.UsedPct) ('{0} of {1} used ({2} %)' -f (Format-SizeGB $vol.UsedGB), (Format-SizeGB $vol.SizeGB), $vol.UsedPct))</div></td>")
            [void]$storageHtml.Append("<td class='mono'>$(Enc (Format-SizeGB $vol.FreeGB))</td><td class='$blCls'>$(V $vol.BitLocker)</td></tr>")
        }
        [void]$storageHtml.Append('</tbody></table>')
    } else {
        [void]$storageHtml.Append("<div class='muted' style='padding:10px 16px;font-size:12px'>$(B 'Kein Laufwerksbuchstabe zugeordnet (z. B. nicht initialisiert oder ohne Partition).' 'No drive letter assigned (e.g. not initialized or without partition).')</div>")
    }
    [void]$storageHtml.Append('</div>')
}

if ($Storage.Count -gt 0 -and $script:StorageErrors.Count -gt 0) {
    [void]$storageHtml.Append("<div class='muted' style='font-size:11px'>$(B 'Hinweis:' 'Note:') $(Enc ($script:StorageErrors -join ' | '))</div>")
}

# --- Datenschutz-Hinweis: listet nur die Verbindungen, die in DIESEM Lauf tatsächlich aufgebaut wurden ---
$connList = New-Object System.Collections.Generic.List[object]
if (-not $KevSkipped) {
    if ($UseCache) { $connList.Add((L 'KEV-Katalog und NVD-Daten: aus dem lokalen Zwischenspeicher (-UseCache), sofern vorhanden' 'KEV catalog and NVD data: from the local cache (-UseCache), if available')) }
    else {
        $connList.Add((L 'CISA (cisa.gov): Abruf des KEV-Katalogs' 'CISA (cisa.gov): download of the KEV catalog'))
        if ($VersionResolved) { $connList.Add((L 'NIST NVD (nvd.nist.gov): Sammelabruf der Daten aller KEV-CVEs (für jedes Gerät gleich), Einzelabfragen nur per CVE-Kennung, keine Inventardaten' 'NIST NVD (nvd.nist.gov): bulk download of the data of all KEV CVEs (same for every device), individual requests only by CVE identifier, no inventory data')) }
    }
}
$ipHosts = (@($OutgoingIPSources | ForEach-Object { ([uri]$_).Host })) -join ' / '
if ($PublicIP) { $connList.Add((L "IP-Dienst ($ipHosts): Ermittlung der öffentlichen IP (Opt-in)" "IP service ($ipHosts): determining the public IP (opt-in)")) }
if ($Latency)  { $connList.Add((L "Ping an $($PingTargets -join ' / ') (Opt-in)" "Ping to $($PingTargets -join ' / ') (opt-in)")) }
if ($Speed)    { $connList.Add((L 'Download der Testdatei von crusadersoft.com (Opt-in, es wird nichts hochgeladen)' 'Download of the test file from crusadersoft.com (opt-in, nothing is uploaded)')) }
$privacyHtml = New-Object System.Text.StringBuilder
[void]$privacyHtml.Append("<section class='privacy' id='datenschutz-hinweis'><b>$(B 'Datenschutz & Vertraulichkeit' 'Privacy & confidentiality')</b>")
[void]$privacyHtml.Append("<p>$(B "Dieser Bericht enthält personenbezogene bzw. personenbeziehbare Daten (z. B. Hostname, lokale Benutzerkonten, IP- und MAC-Adressen, installierte Software). Er wurde lokal erzeugt und liegt unter $HostDir. Bitte nur an Berechtigte weitergeben und nach Gebrauch löschen." "This report contains personal or personally identifiable data (e.g. host name, local user accounts, IP and MAC addresses, installed software). It was created locally and is stored under $HostDir. Share it only with authorized persons and delete it after use.")</p>")
[void]$privacyHtml.Append("<p>$(B 'Verbindungen nach außen bei diesem Lauf (die jeweilige Gegenstelle sieht deine IP-Adresse):' 'Outbound connections in this run (the respective server sees your IP address):')</p><ul>")
if ($connList.Count -eq 0) { [void]$privacyHtml.Append("<li>$(B 'keine' 'none')</li>") }
foreach ($cn in $connList) { [void]$privacyHtml.Append("<li>$(V $cn)</li>") }
[void]$privacyHtml.Append("</ul><p>$(B 'Der Bericht selbst lädt keine externen Inhalte (keine Schriften, Skripte oder Bilder von Dritten) und enthält keine Telemetrie. Weitere Informationen:' 'The report itself loads no external content (no fonts, scripts or images from third parties) and contains no telemetry. More information:') <a href='$PrivacyUrl' target='_blank' rel='noopener noreferrer'>$(B 'Datenschutzerklärung auf crusadersoft.com' 'Privacy policy on crusadersoft.com')</a></p>")
[void]$privacyHtml.Append("<p class='nvd-attr'>This product uses data from the NVD API but is not endorsed or certified by the NVD. $(BH '' '')<span class='l-de'>(Dieses Produkt nutzt Daten der NVD-API, ist aber von der NVD weder empfohlen noch zertifiziert.)</span> Known Exploited Vulnerabilities Catalog: CISA (cisa.gov).</p></section>")

# --- Bedienleiste und Leseanleitung (Knöpfe nutzen nur window.print() bzw. details.open, kein Netzwerk) ---
# Der Report enthält beide Sprachen; der Knopf "Deutsch / English" blendet eine davon aus (Startsprache = Sprache des Laufs).
$toolbarHtml = @'
<div class="toolbar noprint">
<button type="button" class="langbtn" onclick="cwLang()" title="Sprache wechseln / Switch language"><span class="l-de">English</span><span class="l-en">Deutsch</span></button>
<button type="button" onclick="cwPrint(true)"><span class="l-de">Management-Übersicht drucken / als PDF</span><span class="l-en">Print management summary / PDF</span></button>
<button type="button" onclick="cwPrint(false)"><span class="l-de">Gesamten Bericht drucken / als PDF</span><span class="l-en">Print full report / PDF</span></button>
<button type="button" onclick="cwToggle(true)"><span class="l-de">Alle Details aufklappen</span><span class="l-en">Expand all details</span></button>
<button type="button" onclick="cwToggle(false)"><span class="l-de">Alle zuklappen</span><span class="l-en">Collapse all</span></button>
</div>
<details class="howto noprint"><summary><span class="l-de">So lesen Sie diesen Bericht</span><span class="l-en">How to read this report</span></summary><div class="box">
<div class="l-de">
<p><b>Oben steht die Management-Übersicht.</b> Die Ampel zeigt die Dringlichkeit: <b>Rot</b> = mindestens ein kritischer Befund, <b>Orange</b> = mindestens ein hoher Befund, <b>Grün</b> = keine kritischen oder hohen Befunde.</p>
<p><b>Schweregrade:</b> Kritisch = sofort handeln (aktiv ausnutzbar oder grundlegender Schutz fehlt). Hoch = zeitnah einplanen. Mittel = Empfehlung. Hinweis = zur Kenntnis.</p>
<p><b>Darunter folgen die Details für Administratoren.</b> Treffer und Listen sind eingeklappt, ein Klick öffnet sie. Mit den Knöpfen oben lässt sich nur die Übersicht oder der ganze Bericht drucken; im Druckdialog des Browsers &bdquo;Als PDF speichern&ldquo; wählen. Gedruckt wird die gerade angezeigte Sprache.</p>
<p><b>Suche:</b> Im Abschnitt &bdquo;Vollständiges Inventar&ldquo; findet das Suchfeld Programme nach Name, Version oder Hersteller; mehrere Begriffe müssen alle vorkommen, und die Schaltflächen filtern nach Quelle (z. B. Registry, AppX).</p>
<p><b>Grenzen:</b> Der Bericht ist eine Momentaufnahme eines einzelnen Geräts. KEV-Treffer entstehen über Produkt- und Herstellernamen; &bdquo;betroffen&ldquo; gilt erst, wenn die NVD die installierte Version bestätigt. Beschreibungen und Maßnahmen der Schwachstellen stammen von CISA und sind englisch.</p>
<dl>
<dt>KEV</dt><dd>Known Exploited Vulnerabilities: Katalog der US-Behörde CISA mit Schwachstellen, die nachweislich aktiv ausgenutzt werden.</dd>
<dt>CVE</dt><dd>Eindeutige Kennung einer bekannten Schwachstelle, zum Beispiel CVE-2024-12345.</dd>
<dt>NVD</dt><dd>National Vulnerability Database des US-Instituts NIST; liefert unter anderem die betroffenen Versionsbereiche.</dd>
<dt>ESU</dt><dd>Extended Security Updates: kostenpflichtige Sicherheitsupdates nach dem Support-Ende (z. B. Windows 10, Windows Server).</dd>
<dt>BitLocker</dt><dd>Laufwerksverschlüsselung von Windows; schützt Daten bei Verlust oder Diebstahl des Geräts.</dd>
<dt>Secure Boot</dt><dd>UEFI-Funktion, die nur vertrauenswürdige Bootloader startet.</dd>
<dt>VBS / HVCI</dt><dd>Virtualisierungsbasierte Sicherheit und Speicherintegrität: schützen den Windows-Kern vor manipuliertem Code.</dd>
<dt>LSA-Schutz</dt><dd>Schützt den Prozess, der Anmeldedaten verwaltet, vor dem Auslesen.</dd>
<dt>ASR</dt><dd>Attack Surface Reduction: Defender-Regeln, die typische Angriffstechniken blockieren.</dd>
<dt>PUA</dt><dd>Potenziell unerwünschte Anwendungen, zum Beispiel Adware.</dd>
</dl></div>
<div class="l-en">
<p><b>The management summary is at the top.</b> The traffic light shows the urgency: <b>red</b> = at least one critical finding, <b>orange</b> = at least one high finding, <b>green</b> = no critical or high findings.</p>
<p><b>Severities:</b> Critical = act immediately (actively exploitable or basic protection missing). High = schedule soon. Medium = recommendation. Info = for your information.</p>
<p><b>The details for administrators follow below.</b> Hits and lists are collapsed, a click opens them. The buttons at the top print only the summary or the whole report; choose &ldquo;Save as PDF&rdquo; in the browser print dialog. The language currently shown is printed.</p>
<p><b>Search:</b> in the &ldquo;Full inventory&rdquo; section the search box finds programs by name, version or vendor; several terms must all match, and the buttons filter by source (e.g. Registry, AppX).</p>
<p><b>Limits:</b> the report is a snapshot of a single device. KEV hits are based on product and vendor names; &ldquo;affected&rdquo; only applies once the NVD confirms the installed version. Vulnerability descriptions and required actions come from CISA.</p>
<dl>
<dt>KEV</dt><dd>Known Exploited Vulnerabilities: catalog of the US agency CISA listing vulnerabilities that are known to be actively exploited.</dd>
<dt>CVE</dt><dd>Unique identifier of a known vulnerability, for example CVE-2024-12345.</dd>
<dt>NVD</dt><dd>National Vulnerability Database of the US institute NIST; provides, among other things, the affected version ranges.</dd>
<dt>ESU</dt><dd>Extended Security Updates: paid security updates after the end of support (e.g. Windows 10, Windows Server).</dd>
<dt>BitLocker</dt><dd>Windows drive encryption; protects data if the device is lost or stolen.</dd>
<dt>Secure Boot</dt><dd>UEFI feature that only starts trusted boot loaders.</dd>
<dt>VBS / HVCI</dt><dd>Virtualization-based security and memory integrity: protect the Windows kernel against manipulated code.</dd>
<dt>LSA protection</dt><dd>Protects the process that manages credentials against being read out.</dd>
<dt>ASR</dt><dd>Attack Surface Reduction: Defender rules that block typical attack techniques.</dd>
<dt>PUA</dt><dd>Potentially unwanted applications, for example adware.</dd>
</dl></div>
</div></details>
'@
$scriptHtml = @'
<script>
function cwLangNow(){ return document.documentElement.getAttribute('data-lang')==='de' ? 'de' : 'en'; }
function cwLang(to){
  var l = to || (cwLangNow()==='de' ? 'en' : 'de');
  document.documentElement.setAttribute('data-lang', l); document.documentElement.setAttribute('lang', l);
  var q=document.getElementById('invq'); if(q){ q.placeholder=q.getAttribute('data-ph-'+l)||q.placeholder; }
  if(document.title && document.documentElement.getAttribute('data-title-'+l)){ document.title=document.documentElement.getAttribute('data-title-'+l); }
  cwInv();
}
function cwPrint(execOnly){ if(execOnly){ document.body.classList.add('print-exec'); } window.print(); }
window.addEventListener('afterprint', function(){ document.body.classList.remove('print-exec'); });
function cwToggle(open){ var d=document.querySelectorAll('details'); for(var i=0;i<d.length;i++){ d[i].open=open; } }
(function(){ var b=document.createElement('div'); b.id='tipbox'; document.body.appendChild(b);
function show(e){ var t=e.target.closest ? e.target.closest('.tip') : null; if(!t) return; b.textContent=t.getAttribute('data-tip-'+cwLangNow())||t.getAttribute('data-tip-en')||''; b.style.display='block'; var r=t.getBoundingClientRect(), w=b.offsetWidth, h=b.offsetHeight; var x=Math.min(Math.max(8,r.left), window.innerWidth-w-8); var y=r.bottom+8; if(y+h>window.innerHeight-8) y=Math.max(8, r.top-h-8); b.style.left=x+'px'; b.style.top=y+'px'; }
function hide(e){ var t=e.target.closest ? e.target.closest('.tip') : null; if(t) b.style.display='none'; }
document.addEventListener('mouseover',show); document.addEventListener('mouseout',hide); document.addEventListener('focusin',show); document.addEventListener('focusout',hide);
})();
function cwP(r){ var t=r.closest('table'); t.classList.toggle('showp'); }
function cwInv(){
  var qEl=document.getElementById('invq'); if(!qEl){ return; }
  var de=(cwLangNow()==='de'), of=de?' von ':' of ';
  var words=(qEl.value||'').toLowerCase().split(/\s+/).filter(function(w){ return w.length>0; });
  var on={}, chips=document.querySelectorAll('#invchips input'), allOn=true, i, j, k;
  for(i=0;i<chips.length;i++){ on[chips[i].value]=chips[i].checked; if(!chips[i].checked){ allOn=false; } }
  var groups=document.querySelectorAll('details.invgrp'), shown=0, total=0;
  for(i=0;i<groups.length;i++){
    var g=groups[i], src=g.getAttribute('data-src'), rows=g.querySelectorAll('tbody tr'), vis=0;
    for(j=0;j<rows.length;j++){
      var txt=rows[j].textContent.toLowerCase(), ok=(on[src]!==false);
      for(k=0;ok&&k<words.length;k++){ if(txt.indexOf(words[k])<0){ ok=false; } }
      rows[j].style.display=ok?'':'none';
      if(ok){ vis++; }
    }
    total+=rows.length; shown+=vis;
    g.style.display=(vis>0)?'':'none';
    g.open=(words.length>0 && vis>0);
    var cnt=g.querySelector('summary span');
    if(cnt){ cnt.textContent='('+((words.length>0||!allOn)?(vis+of+rows.length):rows.length)+')'; }
  }
  var filtered=(words.length>0||!allOn), ent=de?' Einträge':' entries', ent2=de?' Einträgen':' entries';
  var c=document.getElementById('invcount'); if(c){ c.textContent=filtered?(shown+of+total+ent2):(total+ent); }
  var n=document.getElementById('invnone'); if(n){ n.style.display=(shown===0)?'':'none'; }
}
function cwInvReset(){
  var q=document.getElementById('invq'); if(q){ q.value=''; }
  var chips=document.querySelectorAll('#invchips input'); for(var i=0;i<chips.length;i++){ chips[i].checked=true; }
  cwInv();
}
window.addEventListener('load', function(){ cwLang(cwLangNow()); });
</script>
'@

# --- Speedtest-Kachel (Netzwerk) ---
$speedTile = ''
$SpeedText = L 'übersprungen' 'skipped'
if ($Speed) {
    $SpeedText = if ($Speed.Ok) { L "$($Speed.Text.de) - $($Speed.Detail.de)" "$($Speed.Text.en) - $($Speed.Detail.en)" } else { L "nicht ermittelbar ($($Speed.Detail))" "not determinable ($($Speed.Detail))" }
    $speedTile = "<div class='kv'><div class='k'>$(B 'Download-Geschwindigkeit' 'Download speed')</div><div class='$($Speed.Class)'>$(V $Speed.Text)</div><div class='basis' style='white-space:normal'>$(V $Speed.Detail)</div></div>"
}

# --- Offene Ports (aufklappbar) mit Einordnung: grün = Windows-Standard, gelb = Fernzugriff/ungewöhnlich, rot = veraltet ---
$portsHtml = New-Object System.Text.StringBuilder
$script:PortAttn = @{ risk = @(); unusual = @(); remote = @() }     # je Eintrag ein zweisprachiger Text "Port (Dienst)"
if ($ListenPorts.Count -gt 0) {
    $pinfo = @($ListenPorts | ForEach-Object { [PSCustomObject]@{ P = $_; I = (Get-PortInfo $_.Port $_.ProcessList) } } | Sort-Object { $_.I.Rank }, { $_.P.Port })
    $pc = @{}; foreach ($k in 'risk','unusual','remote','unknown','known','ms') { $pc[$k] = @($pinfo | Where-Object { $_.I.Kind -eq $k }).Count }
    foreach ($k in 'risk','unusual','remote') { $script:PortAttn[$k] = @($pinfo | Where-Object { $_.I.Kind -eq $k } | ForEach-Object { L "$($_.P.Port) ($($_.I.Name.de))" "$($_.P.Port) ($($_.I.Name.en))" }) }
    $miniPills = ''
    foreach ($k in 'risk','unusual','remote','unknown','known','ms') { if ($pc[$k] -gt 0) { $miniPills += " <span class='pill pt-$k'>$($pc[$k]) $(V $script:PortKinds[$k])</span>" } }
    [void]$portsHtml.Append("<details><summary>$(B 'Offene (lauschende) Ports' 'Open (listening) ports') <span class='muted'>($($ListenPorts.Count))</span>$miniPills</summary>")
    [void]$portsHtml.Append("<div class='portintro'>" + (BH "<b>Was sagen offene Ports?</b> Ein lauschender Port ist eine &bdquo;T&uuml;r&ldquo; des Rechners: Ein Programm wartet dort auf Verbindungen von anderen Ger&auml;ten. Jede T&uuml;r vergr&ouml;&szlig;ert die Angriffsfl&auml;che. Aufgelistet sind nur Ports, die von au&szlig;erhalb dieses Rechners erreichbar sind (nicht <span class='mono'>127.0.0.1</span>).<br><span class='pill pt-ms'>Windows-Standard</span> ist normal: ein &uuml;blicher Windows-Dienst auf seinem Standardport, ge&ouml;ffnet vom erwarteten Prozess. <span class='pill pt-remote'>Gelb</span> und <span class='pill pt-risk'>rot</span> verdienen einen Blick (Fernzugriff, veraltete Protokolle, ein Standardport mit untypischem Prozess). <span class='pill pt-unknown'>Grau</span> sind anwendungseigene oder unbekannte Ports: pr&uuml;fen, ob die Software bekannt und gewollt ist. Ob ein Port wirklich aus dem Internet erreichbar ist, h&auml;ngt von Windows-Firewall und Router ab; das pr&uuml;ft dieser Scan nicht. Mit der Maus &uuml;ber der Einordnung erscheint die Erkl&auml;rung zum jeweiligen Port." `
        "<b>What do open ports tell you?</b> A listening port is a &ldquo;door&rdquo; of the computer: a program waits there for connections from other devices. Every door increases the attack surface. Only ports reachable from outside this computer are listed (not <span class='mono'>127.0.0.1</span>).<br><span class='pill pt-ms'>Windows default</span> is normal: a common Windows service on its standard port, opened by the expected process. <span class='pill pt-remote'>Yellow</span> and <span class='pill pt-risk'>red</span> deserve a look (remote access, outdated protocols, a standard port with an atypical process). <span class='pill pt-unknown'>Grey</span> are application-specific or unknown ports: check whether the software is known and intended. Whether a port is really reachable from the internet depends on the Windows firewall and the router; this scan does not check that. Hover over the classification to see the explanation for each port.") + "</div>")
    [void]$portsHtml.Append("<table class='inv'><thead><tr><th>Port</th><th>$(B 'Dienst' 'Service')</th><th>$(TipK (B 'Adresse' 'Address') 'Adresse')</th><th>$(B 'Prozess' 'Process')</th><th>$(B 'Einordnung' 'Classification')</th></tr></thead><tbody>")
    foreach ($x in $pinfo) {
        $addrDe = $x.P.Address -replace '(^|, )(0\.0\.0\.0|::)(?=,|$)', '$1$2 (alle Netzwerke)'
        $addrEn = $x.P.Address -replace '(^|, )(0\.0\.0\.0|::)(?=,|$)', '$1$2 (all networks)'
        [void]$portsHtml.Append("<tr><td class='mono'>$($x.P.Port)</td><td>$(V $x.I.Name)</td><td class='mono muted'>$(B $addrDe $addrEn)</td><td class='muted'>$(Enc $x.P.Process)</td><td>$(Pill "pill pt-$($x.I.Kind)" (V $x.I.Label) $x.I.Hint)</td></tr>")
    }
    [void]$portsHtml.Append('</tbody></table></details>')
} else {
    [void]$portsHtml.Append("<div class='muted' style='font-size:12px'>$(B 'Keine extern lauschenden Ports ermittelt (oder keine Rechte).' 'No externally listening ports found (or no rights).')</div>")
}

$kevDateFmt = try { ([datetime]$kevDate).ToString('yyyy-MM-dd') } catch { "$kevDate" }
$kevHost    = if ($kevSource -match '^https?://') { ($kevSource -split '/')[2] } else { $kevSource }
$kevHostEn  = (($kevHost -replace 'h alt, -UseCache', 'h old, -UseCache') -replace '^Cache \(veraltet, ', 'Cache (outdated, ')
$kevMeta = if ($kev) { B "$kevCount Einträge · Stand $kevDateFmt · Quelle: $kevHost" "$kevCount entries · as of $kevDateFmt · source: $kevHostEn" } else { B 'nicht abrufbar' 'not available' }
$overdueProducts = @($matchedArr | Where-Object { $_.PSObject.Properties['HasOverdue'] -and $_.HasOverdue }).Count
# Offene Produkte: mindestens ein Treffer ist nicht per NVD als "Vermutlich gepatcht" eingestuft (ohne Versionsabgleich: alle)
$nvdSkipped = @($script:NvdSkippedCves).Count      # CVEs ohne NVD-Prüfung (Limit)
$openProducts = @($matchedArr | Where-Object { -not $VersionResolved -or @($_.Hits | Where-Object { $_.VersionVerdict -ne 'Vermutlich gepatcht' }).Count -gt 0 })
$incompleteHtml = ''
if ($nvdSkipped -gt 0) {
    $skipSec = [int]($nvdSkipped * $script:NvdDelayMs / 1000)
    $incompleteHtml = "<div class='incomplete'>" + (BH "<b>Scan unvollst&auml;ndig:</b> F&uuml;r <b>$nvdSkipped CVEs</b> fehlt die Pr&uuml;fung gegen die NVD, weil das Limit von $NvdMaxCves neuen Abfragen pro Lauf erreicht war. Die betroffenen Treffer stehen deshalb auf &bdquo;Unklar&ldquo;, Windows-Eintr&auml;ge k&ouml;nnen fehlen. <b>Bitte den Scan erneut ausf&uuml;hren:</b> was bereits gepr&uuml;ft wurde, ist jetzt gespeichert, es werden die fehlenden CVEs nachgeladen. Alternativ ohne Limit scannen (GUI: Haken &bdquo;NVD-Limit&ldquo; entfernen; Kommandozeile: <span class='mono'>-NoNvdLimit</span>); das dauert ohne API-Key etwa $(Enc (Format-Eta $skipSec 'de')) zus&auml;tzlich." `
        "<b>Scan incomplete:</b> for <b>$nvdSkipped CVEs</b> the check against the NVD is missing, because the limit of $NvdMaxCves new requests per run was reached. The affected hits are therefore &ldquo;Unclear&rdquo;, Windows entries may be missing. <b>Please run the scan again:</b> what has already been checked is now stored, the missing CVEs will be fetched. Alternatively scan without the limit (GUI: untick &ldquo;NVD limit&rdquo;; command line: <span class='mono'>-NoNvdLimit</span>); without an API key this takes about $(Enc (Format-Eta $skipSec 'en')) longer.") + "</div>"
}
$statusClass = if ($affectedCount -gt 0 -or $overdueProducts -gt 0) { 'stat-crit' } elseif ($ransomProducts) { 'stat-crit' } elseif ($openProducts.Count) { 'stat-warn' } else { 'stat-ok' }
$statusLine  = if ($affectedCount -gt 0) { B "$affectedProducts Produkt(e) mit betroffener Version" "$affectedProducts product(s) with affected version" }
               elseif ($openProducts.Count) { B "$($openProducts.Count) Produkte mit KEV-Bezug" "$($openProducts.Count) products with KEV relevance" }
               elseif ($matchedArr.Count) { B "$($matchedArr.Count) KEV-Produkte erkannt, Version laut NVD nicht betroffen" "$($matchedArr.Count) KEV products detected, version not affected according to the NVD" }
               else { B 'Keine KEV-Treffer' 'No KEV hits' }
$verStatus   = if ($VersionResolved) { " &middot; " + (B "$affectedCount Treffer versionsgeprüft betroffen" "$affectedCount hits confirmed affected by version") } else { ' &middot; ' + (B 'Versionsabgleich aus' 'version check off') }
$overdueStatus = if ($overdueProducts -gt 0) { " &middot; " + (B "$overdueProducts mit überfälliger CISA-Frist" "$overdueProducts with overdue CISA due date") } else { '' }

# >>> EXEC-SUMMARY BEGIN
# =====================  EXECUTIVE SUMMARY (Management-Übersicht)  =====================
# Regelbasiert und nachvollziehbar: jeder Befund stammt aus einer expliziten Regel unten (kein Score,
# keine versteckte Gewichtung). Schweregrade: Kritisch > Hoch > Mittel > Hinweis.
# Anpassen = die Regeln hier ändern. "Betroffen" wird nur gemeldet, wenn die NVD die Version bestätigt.
# Alle Texte sind zweisprachig (L 'deutsch' 'english'); Schweregrad, Bereich und Aufwand bleiben intern deutsche Schlüssel.
$findings = New-Object System.Collections.Generic.List[object]
$good     = New-Object System.Collections.Generic.List[object]
$notes    = New-Object System.Collections.Generic.List[object]
$sevOrder = @{ 'Kritisch' = 0; 'Hoch' = 1; 'Mittel' = 2; 'Hinweis' = 3 }
$sevPill  = @{ 'Kritisch' = 's-crit'; 'Hoch' = 's-high'; 'Mittel' = 's-med'; 'Hinweis' = 's-info' }
$script:SevEn    = @{ 'Kritisch' = 'Critical'; 'Hoch' = 'High'; 'Mittel' = 'Medium'; 'Hinweis' = 'Info' }
$script:AreaEn   = @{ 'Schwachstellen' = 'Vulnerabilities'; 'Betriebssystem' = 'Operating system'; 'Datenschutz' = 'Data protection'; 'Plattform' = 'Platform'
                      'Endpoint-Schutz' = 'Endpoint protection'; 'Zugriffsschutz' = 'Access control'; 'Netzwerk-Härtung' = 'Network hardening'
                      'Datenverfügbarkeit' = 'Data availability'; 'Netzwerk' = 'Network' }
$script:EffortEn = @{ 'gering' = 'low'; 'mittel' = 'medium'; 'hoch' = 'high' }
function Add-Finding([string]$Sev, [string]$Area, $Title, $Detail, [string]$Effort, [string]$Anchor) {
    $findings.Add([PSCustomObject]@{ Severity = $Sev; Area = $Area; Title = $Title; Detail = $Detail; Effort = $Effort; Anchor = $Anchor; Order = $findings.Count })
}
function Add-Good($de, $en) { $good.Add((L $de $en)) }
function Add-Note($de, $en) { $notes.Add((L $de $en)) }
function JoinL($items, [string]$lang, [string]$sep = ', ') { (@($items | ForEach-Object { if (Test-L $_) { $_.$lang } else { "$_" } }) -join $sep) }

# --- Schwachstellen (KEV + NVD-Versionsabgleich) ---
if ($KevSkipped) {
    Add-Note 'Der KEV-Abgleich wurde übersprungen: Es gibt keine Aussage zu bekannten, aktiv ausgenutzten Schwachstellen.' 'KEV matching was skipped: there is no statement about known, actively exploited vulnerabilities.'
} else {
    $kevAff     = @($matchedArr | Where-Object { $_.Affected })
    $kevUnclear = @($matchedArr | Where-Object { -not $_.Affected -and @($_.Hits | Where-Object { $_.VersionVerdict -ne 'Vermutlich gepatcht' }).Count -gt 0 })
    $kevPatched = $matchedArr.Count - $kevAff.Count - $kevUnclear.Count
    $kevUrgent  = @($kevUnclear | Where-Object { $_.HasRansom -or ($_.PSObject.Properties['HasOverdue'] -and $_.HasOverdue) })
    $kevRest    = $kevUnclear.Count - $kevUrgent.Count
    if ($kevAff.Count -gt 0) {
        $top3 = @($kevAff | Select-Object -First 3)
        $nDe = (($top3 | ForEach-Object { if ($_.HasRansom) { "$($_.Name) (Ransomware-Bezug)" } else { "$($_.Name)" } }) -join ', ')
        $nEn = (($top3 | ForEach-Object { if ($_.HasRansom) { "$($_.Name) (ransomware use)" } else { "$($_.Name)" } }) -join ', ')
        $mDe = if ($kevAff.Count -gt 3) { " und $($kevAff.Count - 3) weitere" } else { '' }
        $mEn = if ($kevAff.Count -gt 3) { " and $($kevAff.Count - 3) more" } else { '' }
        Add-Finding 'Kritisch' 'Schwachstellen' (L 'Betroffene Software aktualisieren oder entfernen' 'Update or remove affected software') `
            (L "$($kevAff.Count) Produkt(e) mit bestätigt verwundbarer Version, für die aktive Angriffe bekannt sind: $nDe$mDe." "$($kevAff.Count) product(s) with a confirmed vulnerable version for which active attacks are known: $nEn$mEn.") 'mittel' 'sec-kev'
    }
    if ($kevUrgent.Count -gt 0) {
        Add-Finding 'Hoch' 'Schwachstellen' (L 'Dringende KEV-Treffer prüfen (Ransomware-Bezug oder überfällige Frist)' 'Check urgent KEV hits (ransomware use or overdue due date)') `
            (L "$($kevUrgent.Count) Produkt(e), bei denen die Version nicht eindeutig geklärt ist (Zuordnung per Name). Installierte Version prüfen und bei Bedarf aktualisieren." "$($kevUrgent.Count) product(s) whose version could not be clearly determined (matched by name). Check the installed version and update if necessary.") 'gering' 'sec-kev'
    }
    if ($kevRest -gt 0) {
        Add-Finding 'Mittel' 'Schwachstellen' (L 'Weitere KEV-Treffer prüfen' 'Check further KEV hits') `
            (L "$kevRest weitere(s) Produkt(e) tauchen im KEV-Katalog auf; die Version konnte nicht eindeutig bewertet werden." "$kevRest further product(s) appear in the KEV catalog; the version could not be clearly assessed.") 'gering' 'sec-kev'
    }
    if ($matchedArr.Count -eq 0) { Add-Good 'Keine installierte Software im CISA-KEV-Katalog (aktiv ausgenutzte Schwachstellen) gefunden' 'No installed software found in the CISA KEV catalog (actively exploited vulnerabilities)' }
    else {
        # Zählung nach Treffern (CVEs), nicht nach Produkten
        $patchedHitCount = @($matchedArr | ForEach-Object { $_.Hits } | Where-Object { $_.VersionVerdict -eq 'Vermutlich gepatcht' }).Count
        $patchedProdCount = @($matchedArr | Where-Object { @($_.Hits | Where-Object { $_.VersionVerdict -eq 'Vermutlich gepatcht' }).Count -gt 0 }).Count
        if ($patchedHitCount -gt 0) { Add-Good "$patchedHitCount KEV-Treffer in $patchedProdCount Produkt(en) sind laut Versionsabgleich vermutlich bereits gepatcht" "$patchedHitCount KEV hits in $patchedProdCount product(s) are probably already patched according to the version check" }
    }
    if ($VersionResolved -and -not $NvdReachable) { Add-Note 'Die NVD war nicht erreichbar: Versions-Verdikte stehen auf "unklar", ein Befund "bestätigt betroffen" ist in diesem Lauf nicht möglich.' 'The NVD was unreachable: version verdicts are "unclear", a "confirmed affected" finding is not possible in this run.' }
    elseif (-not $VersionResolved)                { Add-Note 'Der Versionsabgleich war deaktiviert: KEV-Treffer sind nur als "zu prüfen" bewertet, nicht als "bestätigt betroffen".' 'The version check was disabled: KEV hits are only rated as "to be checked", not as "confirmed affected".' }
}

# --- Betriebssystem, Updates ---
if ($OSSupportInfo) {
    switch ($OSSupportInfo.State) {
        'eol'     { Add-Finding 'Kritisch' 'Betriebssystem' $OSSupportInfo.Title $OSSupportInfo.Detail 'hoch' 'sec-posture' }
        'soon'    { Add-Finding 'Mittel'   'Betriebssystem' $OSSupportInfo.Title $OSSupportInfo.Detail 'mittel' 'sec-posture' }
        'ok'      { Add-Good "Das Betriebssystem wird vom Hersteller unterstützt ($($OSSupportInfo.Name))" "The operating system is supported by the vendor ($($OSSupportInfo.Name))" }
        default   { Add-Note "Der Support-Status des Betriebssystems ist nicht hinterlegt: $(LT2 $OSSupport 'de')." "The support status of the operating system is not on file: $(LT2 $OSSupport 'en')." }
    }
}

$patchDays = $null
if ("$PatchState" -match 'vor (\d+) Tagen') { $patchDays = [int]$Matches[1] }
$patchOld      = ($null -ne $patchDays -and $patchDays -gt 30)
$rebootPending = ("$RebootState" -match '^JA')
$upDays = $null; try { $upDays = [double]$UptimeDays } catch {}
if ($patchOld -or $rebootPending) {
    $uDe = @(); $uEn = @()
    if ($patchOld)      { $uDe += "letztes installiertes Update vor $patchDays Tagen (laut Windows-Hotfix-Liste)"; $uEn += "last installed update $patchDays days ago (according to the Windows hotfix list)" }
    if ($rebootPending) {
        $uDe += 'ein Neustart steht aus, Updates sind noch nicht wirksam' + $(if ($null -ne $upDays) { " (Gerät läuft seit $([math]::Round($upDays)) Tagen)" } else { '' })
        $uEn += 'a restart is pending, updates are not yet effective' + $(if ($null -ne $upDays) { " (device running for $([math]::Round($upDays)) days)" } else { '' })
    }
    $uSev = if ($patchOld -or ($rebootPending -and $null -ne $upDays -and $upDays -gt 7)) { 'Hoch' } else { 'Mittel' }
    $uTitle = if ($patchOld) { L 'Windows-Updates installieren und Gerät neu starten' 'Install Windows updates and restart the device' } else { L 'Gerät neu starten, damit Updates wirksam werden' 'Restart the device so that updates take effect' }
    $uDeT = $uDe -join '; '; $uEnT = $uEn -join '; '
    Add-Finding $uSev 'Betriebssystem' $uTitle (L ($uDeT.Substring(0,1).ToUpper() + $uDeT.Substring(1) + '.') ($uEnT.Substring(0,1).ToUpper() + $uEnT.Substring(1) + '.')) 'gering' 'sec-posture'
} elseif ($null -ne $patchDays) { Add-Good "Windows-Updates sind aktuell (letztes Update vor $patchDays Tagen)" "Windows updates are current (last update $patchDays days ago)" }

# --- Verschlüsselung, Plattform ---
if ("$BitLocker" -match 'FullyDecrypted|Schutz Off') {
    $blEff = if ("$TPMState" -match '^vorhanden') { 'gering' } else { 'mittel' }
    Add-Finding 'Hoch' 'Datenschutz' (L 'Systemlaufwerk mit BitLocker verschlüsseln' 'Encrypt the system drive with BitLocker') `
        (L 'Das Systemlaufwerk ist nicht durch BitLocker geschützt: Bei Verlust oder Diebstahl des Geräts sind die Daten lesbar.' 'The system drive is not protected by BitLocker: if the device is lost or stolen, the data is readable.') $blEff 'sec-posture'
} elseif ("$BitLocker" -match 'FullyEncrypted' -and "$BitLocker" -match 'Schutz On') { Add-Good 'Das Systemlaufwerk ist mit BitLocker verschlüsselt' 'The system drive is encrypted with BitLocker' }
elseif ("$BitLocker" -match '^n/a') { Add-Note 'Der BitLocker-Status war nicht prüfbar (dafür sind Administratorrechte nötig).' 'The BitLocker status could not be checked (administrator rights are required).' }

if ("$SecureBoot" -eq 'inaktiv') {
    Add-Finding 'Hoch' 'Plattform' (L 'Secure Boot im UEFI aktivieren' 'Enable Secure Boot in the UEFI') `
        (L 'Secure Boot ist ausgeschaltet; manipulierte Bootloader und Bootkits werden nicht abgewehrt. (Bei Legacy-BIOS-Installation ist zuvor die Umstellung auf UEFI/GPT nötig.)' 'Secure Boot is switched off; manipulated boot loaders and bootkits are not blocked. (With a legacy BIOS installation, a conversion to UEFI/GPT is required first.)') 'mittel' 'sec-posture'
} elseif ("$SecureBoot" -eq 'aktiv') { Add-Good 'Secure Boot ist aktiv' 'Secure Boot is active' }

# --- Endpoint-Schutz ---
if ("$AVState" -match '^keine registriert') {
    Add-Finding 'Kritisch' 'Endpoint-Schutz' (L 'Virenschutz installieren bzw. aktivieren' 'Install or enable antivirus protection') (L 'Es ist kein Antivirenprodukt im Windows-Sicherheitscenter registriert.' 'No antivirus product is registered in Windows Security Center.') 'gering' 'sec-defender'
}
$defRt = "$($DefenderItems['Echtzeitschutz'])"
if ($defRt -match 'Risiko' -and "$AVState" -notmatch '^keine registriert' -and $ThirdPartyAV.Count -eq 0) {
    Add-Finding 'Kritisch' 'Endpoint-Schutz' (L 'Defender-Echtzeitschutz aktivieren' 'Enable Defender real-time protection') (L 'Der Echtzeitschutz ist ausgeschaltet, und es ist kein anderer Virenschutz als aktiv gemeldet.' 'Real-time protection is switched off, and no other antivirus is reported as active.') 'gering' 'sec-defender'
} elseif ($defRt -eq 'aktiv') { Add-Good 'Der Defender-Echtzeitschutz ist aktiv' 'Defender real-time protection is active' }
if ("$($DefenderItems['Manipulationsschutz'])" -eq 'aktiv') { Add-Good 'Der Defender-Manipulationsschutz ist aktiv' 'Defender tamper protection is active' }
$defSig = "$($DefenderItems['Signatur-Version'])"
if ($ThirdPartyAV.Count -gt 0) {
    # Anderer Virenschutz aktiv: Defender ist dann bewusst aus, seine Signaturen/Optionen sind kein Befund
    Add-Good "Virenschutz durch $($ThirdPartyAV -join ', ') (laut Windows-Sicherheitscenter)" "Antivirus protection by $($ThirdPartyAV -join ', ') (according to Windows Security Center)"
    $defSig = ''
}
if     ($defSig -match '\(Risiko\)') { Add-Finding 'Hoch'   'Endpoint-Schutz' (L 'Defender-Signaturen aktualisieren' 'Update Defender signatures') (L 'Die Virensignaturen sind älter als 7 Tage.' 'The virus signatures are older than 7 days.') 'gering' 'sec-defender' }
elseif ($defSig -match '\(Hinweis\)') { Add-Finding 'Mittel' 'Endpoint-Schutz' (L 'Defender-Signaturen aktualisieren' 'Update Defender signatures') (L 'Die Virensignaturen sind älter als 2 Tage.' 'The virus signatures are older than 2 days.') 'gering' 'sec-defender' }
elseif ($defSig)                      { Add-Good 'Die Virensignaturen sind aktuell' 'The virus signatures are current' }
$defHints = @($DefenderItems.Keys | Where-Object { $_ -notin 'Signatur-Version', 'Betriebsmodus' -and "$($DefenderItems[$_])" -match '\(Hinweis\)' -and "$($DefenderItems[$_])" -notmatch 'passiv' })
if ($defHints.Count -gt 0 -and $ThirdPartyAV.Count -eq 0) {
    Add-Finding 'Mittel' 'Endpoint-Schutz' (L 'Defender-Schutzfunktionen nachschärfen' 'Tighten Defender protection features') `
        (L ('Nicht aktiv: ' + ($defHints -join ', ') + '.') ('Not active: ' + (($defHints | ForEach-Object { if ($script:LabelEn.ContainsKey($_)) { $script:LabelEn[$_] } else { $_ } }) -join ', ') + '.')) 'gering' 'sec-defender'
}
if ($DefenderItems.Contains('Microsoft Defender')) { Add-Note 'Die Defender-Details waren nicht abrufbar (z. B. Drittanbieter-AV oder fehlende Rechte).' 'The Defender details were not available (e.g. third-party AV or missing rights).' }
if ("$FwState" -match '^3/3') { Add-Good 'Die Windows-Firewall ist in allen Profilen aktiv' 'The Windows firewall is active in all profiles' }
elseif ("$FwState" -match '^\d/3') { Add-Finding 'Hoch' 'Endpoint-Schutz' (L 'Windows-Firewall in allen Profilen aktivieren' 'Enable the Windows firewall in all profiles') (L "Firewall-Status: $(LT2 $FwState 'de')." "Firewall status: $(LT2 $FwState 'en').") 'gering' 'sec-hw' }

# --- Zugriffsschutz, Konfiguration ---
if ("$AutoLogonState" -match 'Risiko') { Add-Finding 'Kritisch' 'Zugriffsschutz' (L 'Automatische Windows-Anmeldung (Autologon) abschalten' 'Switch off automatic Windows logon (autologon)') (L 'Das Gerät meldet sich automatisch an: Wer Zugriff auf das Gerät hat, hat Zugriff auf das Konto.' 'The device logs on automatically: whoever has access to the device has access to the account.') 'gering' 'sec-posture' }
if ("$GuestState" -match 'Risiko')     { Add-Finding 'Kritisch' 'Zugriffsschutz' (L 'Gast-Konto deaktivieren' 'Disable the guest account') (L 'Das Gast-Konto ist aktiviert und ermöglicht Zugriff ohne persönliches Konto.' 'The guest account is enabled and allows access without a personal account.') 'gering' 'sec-posture' }
if ("$SMB1State" -match 'Risiko')      { Add-Finding 'Kritisch' 'Netzwerk-Härtung' (L 'Veraltetes Protokoll SMBv1 deaktivieren' 'Disable the outdated SMBv1 protocol') (L 'SMBv1 hat schwere bekannte Lücken und war Grundlage von Angriffen wie WannaCry.' 'SMBv1 has severe known vulnerabilities and was the basis of attacks such as WannaCry.') 'gering' 'sec-posture' }
if ("$NtlmState" -match 'Risiko')      { Add-Finding 'Kritisch' 'Netzwerk-Härtung' (L 'Veraltete Authentifizierung (LM/NTLMv1) abschalten' 'Switch off outdated authentication (LM/NTLMv1)') (L "$(LT2 $NtlmState 'de')." "$(LT2 $NtlmState 'en').") 'mittel' 'sec-posture' }
if ("$UACState" -match 'Risiko')       { Add-Finding 'Hoch' 'Zugriffsschutz' (L 'Benutzerkontensteuerung (UAC) aktivieren' 'Enable User Account Control (UAC)') (L 'Die UAC ist ausgeschaltet; Programme laufen ohne Rückfrage mit erhöhten Rechten.' 'UAC is switched off; programs run with elevated rights without confirmation.') 'gering' 'sec-posture' }
if ("$RDPState" -cmatch '^AKTIVIERT') {
    Add-Finding 'Hoch' 'Zugriffsschutz' (L 'Remotedesktop (RDP) nur bei Bedarf und abgesichert betreiben' 'Operate Remote Desktop (RDP) only when needed and secured') `
        (L 'RDP ist aktiviert und ein häufiges Einfallstor für Ransomware. Zugriff nur über VPN/Gateway und mit Netzwerkauthentifizierung (NLA).' 'RDP is enabled and a common entry point for ransomware. Access only via VPN/gateway and with Network Level Authentication (NLA).') 'gering' 'sec-posture'
} elseif ("$RDPState" -eq 'deaktiviert') { Add-Good 'Remotedesktop (RDP) ist deaktiviert' 'Remote Desktop (RDP) is disabled' }
if ("$LocalAdmins" -match '^(\d+):' -and [int]$Matches[1] -gt 3) {
    $nAdm = $Matches[1]
    Add-Finding 'Mittel' 'Zugriffsschutz' (L 'Lokale Administratorkonten reduzieren' 'Reduce local administrator accounts') (L "$nAdm lokale Administratorkonten: nach dem Prinzip der minimalen Rechte nur die nötigen belassen." "$nAdm local administrator accounts: keep only the necessary ones according to the principle of least privilege.") 'gering' 'sec-posture'
}
if ("$SmbShares" -match '^(\d+):') { Add-Finding 'Hinweis' 'Netzwerk-Härtung' (L 'Freigaben auf Notwendigkeit prüfen' 'Check shares for necessity') (L "Benutzerdefinierte Netzwerkfreigaben vorhanden: $SmbShares." "Custom network shares present: $SmbShares.") 'gering' 'sec-posture' }
$hardDe = @(); $hardEn = @()
if ("$VBSState"  -match 'Hinweis') { $hardDe += 'Virtualisierungsbasierte Sicherheit'; $hardEn += 'virtualization-based security' }
if ("$HVCIState" -match 'Hinweis') { $hardDe += 'Speicherintegrität (HVCI)'; $hardEn += 'memory integrity (HVCI)' }
if ("$LsaState"  -match 'Hinweis') { $hardDe += 'LSA-Schutz'; $hardEn += 'LSA protection' }
if ($hardDe.Count -gt 0) {
    Add-Finding 'Mittel' 'Plattform' (L 'Erweiterte Windows-Härtung aktivieren' 'Enable advanced Windows hardening') `
        (L ("Nicht aktiv bzw. nicht konfiguriert: " + ($hardDe -join ', ') + '. Schützt Anmeldedaten und Systemkern vor Angriffen; vorher Kompatibilität testen.') ("Not active or not configured: " + ($hardEn -join ', ') + '. Protects credentials and the system kernel against attacks; test compatibility first.')) 'mittel' 'sec-posture'
}

# --- Datenträger ---
foreach ($dev in $Storage) {
    $mdDe = LT2 $dev.Model 'de'; $mdEn = LT2 $dev.Model 'en'
    if ($dev.Health -notmatch '^(Healthy|OK|n/a)$') {
        Add-Finding 'Hoch' 'Datenverfügbarkeit' (L 'Datenträger prüfen und Datensicherung sicherstellen' 'Check the disk and ensure a backup') (L "${mdDe}: Zustand `"$($dev.Health)`"." "${mdEn}: health `"$($dev.Health)`".") 'mittel' 'sec-storage'
    }
    if ($null -ne $dev.Wear -and $dev.Bus -ne 'USB' -and [int]$dev.Wear -ge 80) {
        Add-Finding 'Hoch' 'Datenverfügbarkeit' (L 'SSD bald ersetzen' 'Replace the SSD soon') (L "${mdDe}: $($dev.Wear) % der Lebensdauer verbraucht." "${mdEn}: $($dev.Wear) % of the lifetime used.") 'mittel' 'sec-storage'
    }
    foreach ($vol in $dev.Volumes) {
        if ($vol.UsedPct -ge 90) { Add-Finding 'Hoch' 'Datenverfügbarkeit' (L 'Speicherplatz schaffen' 'Free up disk space') (L ("Laufwerk {0} ist zu {1} % belegt ({2} GB frei)." -f $vol.Laufwerk, $vol.UsedPct, $vol.FreeGB) ("Drive {0} is {1} % full ({2} GB free)." -f $vol.Laufwerk, $vol.UsedPct, $vol.FreeGB)) 'gering' 'sec-storage' }
        elseif ($vol.UsedPct -ge 80) { Add-Finding 'Mittel' 'Datenverfügbarkeit' (L 'Speicherplatz im Blick behalten' 'Keep an eye on disk space') (L ("Laufwerk {0} ist zu {1} % belegt ({2} GB frei)." -f $vol.Laufwerk, $vol.UsedPct, $vol.FreeGB) ("Drive {0} is {1} % full ({2} GB free)." -f $vol.Laufwerk, $vol.UsedPct, $vol.FreeGB)) 'gering' 'sec-storage' }
        if ($dev.Bus -eq 'USB' -and "$($vol.BitLocker)" -match 'FullyDecrypted|Schutz Off') {
            Add-Finding 'Hinweis' 'Datenschutz' (L 'Unverschlüsselten USB-Datenträger prüfen' 'Check unencrypted USB drive') (L "Laufwerk $($vol.Laufwerk) ($mdDe) ist nicht verschlüsselt; bei Verlust sind die Daten lesbar." "Drive $($vol.Laufwerk) ($mdEn) is not encrypted; if lost, the data is readable.") 'gering' 'sec-storage'
        }
    }
}
if ($Storage.Count -gt 0 -and @($Storage | Where-Object { $_.Health -match '^(Healthy|OK)$' }).Count -eq $Storage.Count) { Add-Good 'Alle Datenträger melden den Zustand "gesund"' 'All disks report the status "healthy"' }

# --- Offene Ports (Einordnung siehe Get-PortInfo) ---
if ($script:PortAttn.risk.Count -gt 0)    { Add-Finding 'Hoch'    'Netzwerk' (L 'Veraltete bzw. unverschlüsselte Dienste abschalten' 'Switch off outdated or unencrypted services') (L ('Lauschende Ports mit veralteten oder unverschlüsselten Protokollen: ' + (JoinL $script:PortAttn.risk 'de') + '.') ('Listening ports with outdated or unencrypted protocols: ' + (JoinL $script:PortAttn.risk 'en') + '.')) 'gering' 'sec-net' }
if ($script:PortAttn.unusual.Count -gt 0) { Add-Finding 'Mittel'   'Netzwerk' (L 'Ungewöhnliche Prozesse auf Standardports prüfen' 'Check unusual processes on standard ports') (L ('Diese Standardports werden nicht vom erwarteten Windows-Prozess geöffnet: ' + (JoinL $script:PortAttn.unusual 'de') + '. Prüfen, ob das gewollt ist.') ('These standard ports are not opened by the expected Windows process: ' + (JoinL $script:PortAttn.unusual 'en') + '. Check whether this is intended.')) 'mittel' 'sec-net' }
if ($script:PortAttn.remote.Count -gt 0)  { Add-Finding 'Hinweis'  'Netzwerk' (L 'Ports für Fernzugriff auf Notwendigkeit prüfen' 'Check remote access ports for necessity') (L ('Fernzugriff möglich über: ' + (JoinL $script:PortAttn.remote 'de') + '. Nur aktiv lassen, wenn gewollt; nie direkt aus dem Internet erreichbar machen.') ('Remote access possible via: ' + (JoinL $script:PortAttn.remote 'en') + '. Only keep enabled if intended; never make directly reachable from the internet.')) 'gering' 'sec-net' }

# --- Unvollständiger NVD-Abgleich (Limit) ---
if ($nvdSkipped -gt 0) { Add-Finding 'Hoch' 'Schwachstellen' (L 'Scan erneut ausführen: NVD-Prüfung unvollständig' 'Run the scan again: NVD check incomplete') (L "$nvdSkipped CVEs wurden wegen des Limits von $NvdMaxCves neuen NVD-Abfragen nicht geprüft. Scan erneut starten (Cache hilft) oder ohne Limit scannen." "$nvdSkipped CVEs were not checked because of the limit of $NvdMaxCves new NVD requests. Start the scan again (the cache helps) or scan without the limit.") 'gering' 'sec-kev' }

# --- Netzwerk ---
if ($Speed -and $Speed.Ok -and $Speed.Rating -in 'Mangelhaft', 'Ungenügend') {
    Add-Finding 'Hinweis' 'Netzwerk' (L 'Internetanbindung prüfen' 'Check the internet connection') (L ("Download nur {0:N2} Mbit/s ({1}); Momentaufnahme, bitte wiederholen." -f $Speed.Mbps, $Speed.Rating) ("Download only {0:N2} Mbit/s ({1}); snapshot, please repeat." -f $Speed.Mbps, ($Speed.Text.en -replace ' \(.*$', ''))) 'mittel' 'sec-net'
}

# --- Aussagekraft des Scans ---
# >>> ABDECKUNG-NOTES
if ($nvdSkipped -gt 0) { Add-Note "UNVOLLSTÄNDIG: Für $nvdSkipped CVEs fehlt die NVD-Prüfung (Limit von $NvdMaxCves neuen Abfragen pro Lauf). Bitte den Scan erneut ausführen oder mit -NoNvdLimit (GUI: Haken beim NVD-Limit entfernen) scannen." "INCOMPLETE: the NVD check is missing for $nvdSkipped CVEs (limit of $NvdMaxCves new requests per run). Please run the scan again or scan with -NoNvdLimit (GUI: untick the NVD limit)." }
if (-not $KevSkipped) {
    # Windows selbst: Build-Abgleich (Ergebnis) bzw. warum er nicht stattfand
    if ($script:OsCheck -and $script:OsCheck.Done -and $script:OsCheck.Tally) {
        $t = $script:OsCheck.Tally; $oc = $script:OsCheck
        $considered = $oc.Total - $oc.Old
        if ($t.KeyUnknown -gt 0) {
            Add-Note "Windows-Build ($($oc.Name), $($oc.Build)): Die NVD führt dieses Release ($($oc.Key)) bei keiner der $($t.KeyUnknown + $t.NoData) geprüften KEV-Einträge auf; vermutlich ist es dort noch nicht erfasst. Der Build-Abgleich ist daher nicht aussagekräftig (keine Entwarnung). Windows Update auf aktuellen Stand prüfen." `
                     "Windows build ($($oc.Name), $($oc.Build)): the NVD does not list this release ($($oc.Key)) for any of the $($t.KeyUnknown + $t.NoData) checked KEV entries; it is probably not yet recorded there. The build check is therefore not meaningful (no all-clear). Check that Windows Update is current."
        } elseif ($considered -gt 0 -and $t.NoData -ge $considered) {
            Add-Note "Windows-Build ($($oc.Name), $($oc.Build)): Der Build-Abgleich konnte nicht durchgeführt werden, die NVD hat nicht geantwortet bzw. die Obergrenze für Abfragen war erreicht." "Windows build ($($oc.Name), $($oc.Build)): the build check could not be performed, the NVD did not answer or the request limit was reached."
        } else {
            $unc  = $t.Unbounded + $t.NoCpe
            $pDe = "Von $($oc.Total) KEV-Einträgen zu Windows betreffen dich $($t.Affected) (Build zu alt), $($t.Patched) sind in deinem Build behoben, $($t.NotListed) betreffen laut NVD nur andere Windows-Releases"
            $pEn = "Of $($oc.Total) KEV entries for Windows, $($t.Affected) affect you (build too old), $($t.Patched) are fixed in your build, $($t.NotListed) only affect other Windows releases according to the NVD"
            if ($unc -gt 0)     { $pDe += ", bei $unc ist die Lage unklar (die NVD nennt keine Build-Grenze)"; $pEn += ", for $unc the situation is unclear (the NVD gives no build boundary)" }
            if ($t.NoData -gt 0){ $pDe += "; $($t.NoData) ohne NVD-Antwort bzw. nicht abgefragt"; $pEn += "; $($t.NoData) without NVD answer or not queried" }
            if ($oc.Old -gt 0)  { $pDe += "; $($oc.Old) Einträge sind älter als das Release und wurden nicht einzeln geprüft (mit -OsAllYears nachholen)"; $pEn += "; $($oc.Old) entries are older than the release and were not checked individually (catch up with -OsAllYears)" }
            Add-Note "Windows-Build geprüft: $($oc.Name), Build $($oc.Build) ($($oc.Key)). $pDe." "Windows build checked: $($oc.Name), build $($oc.Build) ($($oc.Key)). $pEn."
        }
    } elseif ($script:KevStats -and $script:KevStats.OsEntries -gt 0) {
        $osPct = [math]::Round(100.0 * $script:KevStats.OsEntries / [math]::Max(1, $script:KevStats.Total))
        $whyDe = if ($script:OsCheck -and "$($script:OsCheck.Why)") { " Grund: $(LT2 $script:OsCheck.Why 'de')." } else { '' }
        $whyEn = if ($script:OsCheck -and "$($script:OsCheck.Why)") { " Reason: $(LT2 $script:OsCheck.Why 'en')." } else { '' }
        $phDe  = if ("$PatchState") { " Letzter Hotfix: $(LT2 $PatchState 'de')." } else { '' }
        $phEn  = if ("$PatchState") { " Last hotfix: $(LT2 $PatchState 'en')." } else { '' }
        Add-Note "Das Windows-Betriebssystem selbst wurde nicht per Build geprüft: $($script:KevStats.OsEntries) von $($script:KevStats.Total) KEV-Einträgen ($osPct %) betreffen Windows.$whyDe$phDe" `
                 "The Windows operating system itself was not checked by build: $($script:KevStats.OsEntries) of $($script:KevStats.Total) KEV entries ($osPct %) concern Windows.$whyEn$phEn"
    }
    # Installierte Programme mit bekannter Lücke im Abgleich
    foreach ($g in @(Get-CoverageGaps @($invClean | Where-Object { $_.Source -ne 'Service' } | ForEach-Object { $_.Name }))) {
        $mDe = ''; $mEn = ''
        if ("$($g.Label)" -like 'Microsoft 365*') {
            # Click-to-Run: Version und Update-Status aus der Registry (die NVD kennt für Microsoft 365 Apps keine Build-Grenzen)
            try {
                $c2r = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction Stop
                $updDe = if ("$($c2r.UpdatesEnabled)" -eq 'True') { 'aktiv' } elseif ("$($c2r.UpdatesEnabled)" -eq 'False') { 'NICHT aktiv' } else { 'unbekannt' }
                $updEn = if ("$($c2r.UpdatesEnabled)" -eq 'True') { 'active' } elseif ("$($c2r.UpdatesEnabled)" -eq 'False') { 'NOT active' } else { 'unknown' }
                if ($c2r.VersionToReport) { $mDe = " Installiert: Version $($c2r.VersionToReport), automatische Updates: $updDe."; $mEn = " Installed: version $($c2r.VersionToReport), automatic updates: $updEn." }
            } catch {}
        }
        Add-Note "$($g.Label.de) erkannt ($($g.Items -join ', ')): $($g.Note.de)$mDe" "$($g.Label.en) detected ($($g.Items -join ', ')): $($g.Note.en)$mEn"
    }
    # Treffer, die nicht gegen die NVD geprüft wurden (Obergrenze) bzw. unklar blieben
    $covHits = @($matchedArr | ForEach-Object { $_.Hits })
    $capped  = @($covHits | Where-Object { "$($_.VerdictReason)" -like '*nicht abgefragt*' }).Count
    if ($capped -gt 0) { Add-Note "Nicht gegen die NVD geprüft (Limit von $NvdMaxCves neuen Abfragen pro Lauf; erneut scannen oder -NoNvdLimit nutzen): $capped Treffer (Verdikt: Unklar)." "Not checked against the NVD (limit of $NvdMaxCves new requests per run; scan again or use -NoNvdLimit): $capped hits (verdict: unclear)." }
    $covUnc = @($covHits | Where-Object { $_.VersionVerdict -eq 'Unklar' })
    if ($VersionResolved -and $covUnc.Count -gt 0) {
        $grp = @($covUnc | Group-Object { "$($_.VerdictReason)" } | Sort-Object Count -Descending | Select-Object -First 2)
        $short = { param($x) $x = (($x -replace '\s+', ' ').TrimEnd('.')); if ($x.Length -gt 110) { $x.Substring(0, 107) + '...' } else { $x } }
        $tDe = @($grp | ForEach-Object { '{0}x: {1}' -f $_.Count, (& $short (LT2 $_.Group[0].VerdictReason 'de')) })
        $tEn = @($grp | ForEach-Object { '{0}x: {1}' -f $_.Count, (& $short (LT2 $_.Group[0].VerdictReason 'en')) })
        Add-Note "$($covUnc.Count) von $($covHits.Count) KEV-Treffern sind unklar (häufigste Gründe: $($tDe -join ' | '))." "$($covUnc.Count) of $($covHits.Count) KEV hits are unclear (most common reasons: $($tEn -join ' | '))."
    }
}
# <<< ABDECKUNG-NOTES
if ($RunAsSystem) { Add-Note 'Der Scan lief als SYSTEM: Software, die nur für einzelne Benutzer installiert ist, wird nur für gerade angemeldete Benutzer erfasst; winget-Daten fehlen.' 'The scan ran as SYSTEM: software installed only for individual users is included only for users who are currently signed in; winget data are missing.' }
if ($script:InvOtherUsers.Count -gt 0) { Add-Note "Zusätzlich erfasst: nur für einzelne Benutzer installierte Software von $($script:InvOtherUsers -join ', ')." "Also included: software installed only for individual users of $($script:InvOtherUsers -join ', ')." }
if ("$AdminState" -match '^nein') { Add-Note 'Der Scan lief ohne Administratorrechte: BitLocker-Status, Defender-Ausschlüsse und SSD-Gesundheitswerte sind nur eingeschränkt prüfbar.' 'The scan ran without administrator rights: BitLocker status, Defender exclusions and SSD health values can only be checked to a limited extent.' }
Add-Note 'Betrachtet wurde ausschließlich dieses eine Gerät. Aussagen über Netzwerk oder weitere Geräte sind nicht möglich.' 'Only this one device was examined. No statements about the network or other devices are possible.'
Add-Note 'Die Zuordnung von Software zu KEV-Einträgen beruht auf Namen und Herstellern (Fehlzuordnungen möglich); "bestätigt betroffen" gilt nur nach NVD-Versionsprüfung.' 'The matching of software to KEV entries is based on names and vendors (mismatches possible); "confirmed affected" only applies after the NVD version check.'

# --- Auswertung ---
$sorted = @($findings | Sort-Object @{ Expression = { $sevOrder[$_.Severity] } }, Order)
$cK = @($sorted | Where-Object { $_.Severity -eq 'Kritisch' }).Count
$cH = @($sorted | Where-Object { $_.Severity -eq 'Hoch' }).Count
$cM = @($sorted | Where-Object { $_.Severity -eq 'Mittel' }).Count
$cI = @($sorted | Where-Object { $_.Severity -eq 'Hinweis' }).Count
if     ($cK -gt 0) { $ragCls = 'rag-red';   $ragTxt = L 'Handlungsbedarf: sofort' 'Action required: immediately' }
elseif ($cH -gt 0) { $ragCls = 'rag-amber'; $ragTxt = L 'Handlungsbedarf: zeitnah' 'Action required: soon' }
else               { $ragCls = 'rag-green'; $ragTxt = if (($cM + $cI) -gt 0) { L 'Unauffällig, mit Empfehlungen' 'Inconspicuous, with recommendations' } else { L 'Unauffällig' 'Inconspicuous' } }
$areas = @($sorted | Where-Object { $_.Severity -in 'Kritisch', 'Hoch' } | Group-Object Area | Sort-Object Count -Descending | Select-Object -First 2 | ForEach-Object { $_.Name })
$leadDe = "Befunde auf $($HostName): $cK kritisch, $cH hoch, $cM mittel, $cI Hinweis."
$leadEn = "Findings on $($HostName): $cK critical, $cH high, $cM medium, $cI info."
if ($areas.Count -gt 0) { $leadDe += " Schwerpunkt: $($areas -join ' und ')."; $leadEn += " Focus: $((($areas | ForEach-Object { $script:AreaEn[$_] }) -join ' and ').ToLowerInvariant())." }
if ($cK -gt 0)     { $leadDe += ' Zuerst die kritischen Punkte beheben, danach die hohen.'; $leadEn += ' Fix the critical items first, then the high ones.' }
elseif ($cH -gt 0) { $leadDe += ' Die hohen Punkte zeitnah einplanen.'; $leadEn += ' Schedule the high items soon.' }
else               { $leadDe += ' Es gibt keine kritischen oder hohen Befunde.'; $leadEn += ' There are no critical or high findings.' }

$top = @($sorted | Where-Object { $_.Severity -in 'Kritisch', 'Hoch' } | Select-Object -First 5)
$topHeading = L 'Jetzt zuerst erledigen' 'Do this first'
if ($top.Count -eq 0) { $top = @($sorted | Where-Object { $_.Severity -eq 'Mittel' } | Select-Object -First 3); $topHeading = L 'Empfehlungen' 'Recommendations' }

$execHtml = New-Object System.Text.StringBuilder
[void]$execHtml.Append("<section class='exec' id='exec'><div class='exec-head'><div class='exec-title'>$(B 'Management-Übersicht' 'Management summary')</div><div class='rag $ragCls'><span class='dot'></span>$(V $ragTxt)</div></div>")
[void]$execHtml.Append("<p class='exec-lead'>$(B $leadDe $leadEn)</p>")
[void]$execHtml.Append("<div class='sev-grid'><div class='sev sev-crit'><div class='n'>$cK</div><div class='l'>$(B 'Kritisch' 'Critical')</div></div><div class='sev sev-high'><div class='n'>$cH</div><div class='l'>$(B 'Hoch' 'High')</div></div><div class='sev sev-med'><div class='n'>$cM</div><div class='l'>$(B 'Mittel' 'Medium')</div></div><div class='sev sev-info'><div class='n'>$cI</div><div class='l'>$(B 'Hinweis' 'Info')</div></div></div>")
[void]$execHtml.Append("<h3 class='subhead'>$(V $topHeading)</h3>")
if ($top.Count -gt 0) {
    [void]$execHtml.Append("<ol class='todo'>")
    foreach ($fd in $top) {
        [void]$execHtml.Append("<li><div class='t'><span class='pill $($sevPill[$fd.Severity])'>$(Bmap $fd.Severity $script:SevEn)</span>$(V $fd.Title)<span class='eff'>$(B 'Aufwand:' 'Effort:') $(Bmap $fd.Effort $script:EffortEn)</span></div><div class='d'>$(V $fd.Detail)</div><a class='jump' href='#$($fd.Anchor)'>$(B 'Details im Bericht' 'Details in the report') &rarr;</a></li>")
    }
    [void]$execHtml.Append('</ol>')
} else {
    [void]$execHtml.Append("<div class='ok-banner'>$(B 'Keine Maßnahmen mit Dringlichkeit festgestellt.' 'No urgent actions identified.')</div>")
}
if ($good.Count -gt 0) {
    [void]$execHtml.Append("<h3 class='subhead'>$(B 'Das ist in Ordnung' 'This is fine')</h3><ul class='good'>")
    foreach ($gd in ($good | Select-Object -First 6)) { [void]$execHtml.Append("<li>$(V $gd)</li>") }
    [void]$execHtml.Append('</ul>')
}
[void]$execHtml.Append("<h3 class='subhead'>$(B 'Aussagekraft dieses Scans' 'Scope of this scan')</h3><ul class='notes'>")
foreach ($nt in $notes) { [void]$execHtml.Append("<li>$(V $nt)</li>") }
[void]$execHtml.Append('</ul>')
if ($sorted.Count -gt 0) {
    [void]$execHtml.Append("<details><summary>$(B 'Alle Befunde' 'All findings') <span class='muted'>($($sorted.Count))</span></summary><table class='inv'><thead><tr><th>$(B 'Schweregrad' 'Severity')</th><th>$(B 'Bereich' 'Area')</th><th>$(B 'Maßnahme' 'Action')</th><th>$(B 'Befund' 'Finding')</th><th>$(B 'Aufwand' 'Effort')</th></tr></thead><tbody>")
    foreach ($fd in $sorted) {
        [void]$execHtml.Append("<tr><td><span class='pill $($sevPill[$fd.Severity])'>$(Bmap $fd.Severity $script:SevEn)</span></td><td>$(Bmap $fd.Area $script:AreaEn)</td><td>$(V $fd.Title)</td><td class='muted'>$(V $fd.Detail)</td><td class='muted'>$(Bmap $fd.Effort $script:EffortEn)</td></tr>")
    }
    [void]$execHtml.Append('</tbody></table></details>')
}
[void]$execHtml.Append("<p class='hint' style='margin:14px 0 0'>$(B 'Vertraulich: enthält personenbezogene Daten dieses Geräts. Nur an Berechtigte weitergeben.' 'Confidential: contains personal data of this device. Share only with authorized persons.')</p></section>")

# Maschinenlesbar für spätere Multi-Report-Auswertung (Texte in der Sprache des Laufs, Schweregrad zusätzlich als fester Schlüssel)
try {
    $sevKey = @{ 'Kritisch' = 'critical'; 'Hoch' = 'high'; 'Mittel' = 'medium'; 'Hinweis' = 'info' }
    $tr = { param($v, $map) if ($script:Lang -eq 'de') { "$v" } elseif ($map.ContainsKey("$v")) { $map["$v"] } else { "$v" } }
    [PSCustomObject]@{
        host = $HostName; version = $ScriptVersion; lang = $script:Lang; date = (Get-Date).ToString('yyyy-MM-dd HH:mm'); rating = (LT $ragTxt); admin = [bool]("$AdminState" -match '^ja')
        counts = [ordered]@{ critical = $cK; high = $cH; medium = $cM; info = $cI }
        findings = @($sorted | ForEach-Object { [ordered]@{ severity_key = $sevKey[$_.Severity]; severity = (& $tr $_.Severity $script:SevEn); area = (& $tr $_.Area $script:AreaEn); title = (LT $_.Title); detail = (LT $_.Detail); effort = (& $tr $_.Effort $script:EffortEn) } })
        positives = @($good | ForEach-Object { LT $_ }); notes = @($notes | ForEach-Object { LT $_ })
    } | ConvertTo-Json -Depth 5 | Out-File (Join-Path $HostDir "$HostName$ScanStamp.summary.json") -Encoding UTF8
} catch {}
# <<< EXEC-SUMMARY END

[void]$sb.Append(@"
<!DOCTYPE html><html lang="$($script:Lang)" data-lang="$($script:Lang)" data-title-de="CVEwatch Bericht - $(Enc $HostName)" data-title-en="CVEwatch report - $(Enc $HostName)"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(Enc (G "CVEwatch Bericht - $HostName" "CVEwatch report - $HostName"))</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2230;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
--red:#ff5c5c;--amber:#f0a020;--green:#3fb950;--blue:#58a6ff;--mono:ui-monospace,"Cascadia Code",Consolas,monospace;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,"Segoe UI",Roboto,sans-serif;line-height:1.5;font-size:14px}
.wrap{max-width:1100px;margin:0 auto;padding:32px 20px 80px}
header{border-bottom:1px solid var(--border);padding-bottom:20px;margin-bottom:28px}
.brand{font-family:var(--mono);font-size:12px;letter-spacing:2px;color:var(--muted);text-transform:uppercase}
h1{font-size:26px;margin:6px 0 2px;font-weight:650}
.sub{color:var(--muted);font-size:13px}
.status{display:inline-flex;align-items:center;gap:10px;margin-top:16px;padding:10px 16px;border-radius:8px;border:1px solid var(--border);font-weight:600}
.stat-crit{background:rgba(255,92,92,.12);border-color:var(--red);color:var(--red)}
.stat-warn{background:rgba(240,160,32,.12);border-color:var(--amber);color:var(--amber)}
.stat-ok{background:rgba(63,185,80,.12);border-color:var(--green);color:var(--green)}
h2{font-size:16px;margin:36px 0 14px;padding-bottom:8px;border-bottom:1px solid var(--border);font-weight:600}
h2 .count{color:var(--muted);font-weight:400;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px}
.kv{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px 14px}
.kv .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.kv .v{font-family:var(--mono);font-size:13px;margin-top:3px;word-break:break-all}
.kv .v.warn{color:var(--red);font-weight:600}
.kv .v.caution{color:var(--amber)}
.mcard{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--red);border-radius:8px;margin-bottom:10px;overflow:hidden}
.mcard>summary.mhead{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:12px 16px;background:var(--surface2);flex-wrap:wrap;cursor:pointer;list-style:none}
.mcard>summary.mhead::-webkit-details-marker{display:none}
.mcard>summary.mhead::before{content:'\25B8';color:var(--muted);margin-right:6px;display:inline-block;transition:transform .15s}
.mcard[open]>summary.mhead::before{transform:rotate(90deg)}
.mname{font-weight:650;font-size:15px;flex:1}
.mmeta{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.mver{font-family:var(--mono);color:var(--muted);font-size:12px;margin-left:10px;font-weight:400}
.pill{display:inline-block;font-size:11px;padding:3px 9px;border-radius:20px;font-weight:600}
.pill.ransom{background:rgba(240,160,32,.18);color:var(--amber);border:1px solid var(--amber)}
.pill.count{background:rgba(255,92,92,.12);color:var(--red);border:1px solid rgba(255,92,92,.4)}
.pill.src{background:var(--bg);color:var(--muted);border:1px solid var(--border)}
.vname{color:var(--text);font-size:12px}
.cdesc{color:var(--text);font-size:12px;line-height:1.45;margin-top:4px}
.cdesc>summary{padding:0;font-weight:400;font-size:12px;list-style:none;user-select:auto}
.cdesc>summary::-webkit-details-marker{display:none}
.cd-more,.cd-less{color:var(--blue);font-size:11px;white-space:nowrap}
.cd-less{display:none}
.cdesc[open] .cd-short,.cdesc[open] .cd-more{display:none}
.cdesc[open] .cd-less{display:inline}
.cd-full{margin-top:2px}
.cvs{display:inline-block;margin-top:5px;font-size:10px;font-weight:600;padding:2px 7px;border-radius:4px;border:1px solid transparent;white-space:nowrap;font-family:var(--mono)}
.cvs-crit{background:var(--red);color:#fff;border-color:var(--red)}
.cvs-high{background:rgba(255,92,92,.15);color:var(--red);border-color:var(--red)}
.cvs-med{background:rgba(240,160,32,.15);color:var(--amber);border-color:var(--amber)}
.cvs-low{background:var(--surface2);color:var(--muted);border-color:var(--border)}
.vbox{margin-top:6px;display:grid;gap:3px}
.vrow{display:flex;gap:8px;font-size:11px;align-items:baseline}
.vl{color:var(--muted);min-width:66px;flex:none}
.vx{color:var(--text);display:flex;flex-wrap:wrap;gap:4px}
.rng{font-family:var(--mono);font-size:11px;padding:1px 6px;border-radius:4px;background:var(--surface2);color:var(--muted);border:1px solid var(--border);white-space:nowrap}
.rng-hit{background:rgba(255,92,92,.15);color:var(--red);border-color:var(--red);font-weight:600}
.rng-more{color:var(--muted);font-size:11px;cursor:help}
.vwhy{font-size:10px;color:var(--muted);margin-top:3px;line-height:1.35;max-width:260px}
/* Scan unvollständig */
.incomplete{background:rgba(240,160,32,.12);border:1px solid var(--amber);border-left:4px solid var(--amber);border-radius:8px;padding:12px 16px;margin:0 0 14px;font-size:13px;line-height:1.55;color:var(--text)}
/* Hover-Erklärungen */
.tip{cursor:help;border-bottom:1px dotted var(--muted)}
.pill.tip,.conf.tip,.cvs.tip,.dot.tip,.neu.tip{border-bottom:none}
.dot.tip{width:9px;height:9px}
#tipbox{display:none;position:fixed;z-index:9999;max-width:360px;background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:9px 12px;font-size:12px;font-weight:400;line-height:1.5;box-shadow:0 8px 24px rgba(0,0,0,.4);pointer-events:none;text-align:left;white-space:normal}
@media print{.tip{border-bottom:none}#tipbox{display:none!important}}
/* Offene Ports */
.portintro{font-size:12px;color:var(--muted);line-height:1.6;margin:8px 0 10px}
.pt-ms{background:rgba(63,185,80,.15);color:var(--green)}
.pt-remote,.pt-unusual{background:rgba(240,160,32,.15);color:var(--amber)}
.pt-risk{background:rgba(255,92,92,.15);color:var(--red)}
.pt-known{background:rgba(88,166,255,.12);color:var(--blue,#58a6ff)}
.pt-unknown{background:var(--surface2);color:var(--muted)}
table.cve tr.phid{display:none}
table.cve.showp tr.phid{display:table-row}
tr.ptoggle td{cursor:pointer;color:var(--blue,#58a6ff);font-size:12px;padding:8px 12px;background:var(--surface2)}
tr.ptoggle:hover td{text-decoration:underline}
@media print{table.cve tr.phid{display:table-row}tr.ptoggle{display:none}}
.action{color:var(--muted);font-size:11px;margin-top:3px;font-style:italic}
table{width:100%;border-collapse:collapse}
.cve th,.cve td,.inv th,.inv td{text-align:left;padding:8px 16px;border-top:1px solid var(--border);vertical-align:top}
.cve th,.inv th{color:var(--muted);font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-top:none}
.mono{font-family:var(--mono);font-size:12px}
.muted{color:var(--muted)}
.cve a{color:var(--blue);text-decoration:none}.cve a:hover{text-decoration:underline}
.desc{color:var(--muted);font-size:12px;max-width:460px}
.conf{font-size:11px;padding:2px 8px;border-radius:4px;font-weight:600;white-space:nowrap}
.c-high{background:rgba(255,92,92,.15);color:var(--red)}
.c-med{background:rgba(240,160,32,.15);color:var(--amber)}
.c-low{background:var(--surface2);color:var(--muted)}
.basis{font-size:10px;color:var(--muted);margin-top:3px;white-space:nowrap}
.pill.vbad{background:rgba(255,92,92,.15);color:var(--red);border:1px solid var(--red)}
.pill.vok{background:rgba(63,185,80,.13);color:var(--green);border:1px solid rgba(63,185,80,.5)}
.pill.vunk{background:var(--bg);color:var(--muted);border:1px solid var(--border)}
.vver{font-size:10px;margin-top:4px;padding:1px 6px;border-radius:4px;display:inline-block;font-weight:600}
.vv-bad{background:rgba(255,92,92,.15);color:var(--red)}
.vv-ok{background:rgba(63,185,80,.13);color:var(--green)}
.vv-unk{background:var(--surface2);color:var(--muted)}
td.due-warn{color:var(--red);font-weight:600}
td.due-caution{color:var(--amber)}
.neu{display:inline-block;font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;background:rgba(63,185,80,.18);color:var(--green);border:1px solid var(--green)}
.pill.neu{background:rgba(63,185,80,.16);color:var(--green);border:1px solid var(--green)}
.newbanner{background:rgba(88,166,255,.1);border:1px solid var(--blue);color:var(--blue);padding:12px 16px;border-radius:8px;margin-bottom:14px;font-size:13px}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--amber);vertical-align:middle}
.ok-banner{background:rgba(63,185,80,.1);border:1px solid var(--green);color:var(--green);padding:16px;border-radius:8px}
.nvdwarn{background:rgba(240,160,32,.1);border:1px solid var(--amber);color:var(--amber);padding:12px 16px;border-radius:8px;margin-bottom:14px;font-size:13px}
details{background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-bottom:8px}
summary{cursor:pointer;padding:12px 16px;font-weight:600;user-select:none}
details table{margin-bottom:8px}
.note{margin-top:40px;padding:16px 18px;background:var(--surface);border:1px solid var(--border);border-radius:8px;color:var(--muted);font-size:12.5px}
.note b{color:var(--text)}
footer{margin-top:24px;color:var(--muted);font-size:11px;text-align:center;font-family:var(--mono)}
.kv .v.good{color:var(--green)}
h3.subhead{font-size:12px;margin:22px 0 10px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.6px}
.disk{background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-bottom:10px;overflow:hidden}
.disk .dhead{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;padding:12px 16px;background:var(--surface2)}
.disk .dname{font-weight:650;font-size:14px;flex:1}
.disk .dsize{font-family:var(--mono);color:var(--muted);font-size:12px;margin-left:10px;font-weight:400}
.disk table{margin:0}
.bar{height:8px;background:var(--bg);border:1px solid var(--border);border-radius:5px;overflow:hidden;min-width:140px}
.bar span{display:block;height:100%;background:var(--blue)}
.bar span.mid{background:var(--amber)}
.bar span.hi{background:var(--red)}
.exec{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px 22px;margin:22px 0 8px}
.exec-head{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap}
.exec-title{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;font-weight:600}
.rag{display:inline-flex;align-items:center;gap:10px;font-weight:700;font-size:15px;padding:8px 16px;border-radius:8px;border:1px solid var(--border)}
.rag .dot{width:14px;height:14px;border-radius:50%;display:inline-block}
.rag-red{border-color:var(--red);color:var(--red);background:rgba(255,92,92,.1)}
.rag-red .dot{background:var(--red)}
.rag-amber{border-color:var(--amber);color:var(--amber);background:rgba(240,160,32,.1)}
.rag-amber .dot{background:var(--amber)}
.rag-green{border-color:var(--green);color:var(--green);background:rgba(63,185,80,.1)}
.rag-green .dot{background:var(--green)}
.exec-lead{font-size:15px;line-height:1.5;margin:14px 0 4px}
.sev-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0 4px}
.sev{border:1px solid var(--border);border-radius:8px;padding:12px 14px;background:var(--bg)}
.sev .n{font-size:28px;font-weight:700;line-height:1}
.sev .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:4px}
.sev-crit .n{color:var(--red)}
.sev-high .n{color:var(--amber)}
.sev-med .n{color:var(--blue)}
.sev-info .n{color:var(--muted)}
ol.todo{list-style:none;counter-reset:t;margin:8px 0 0;padding:0}
ol.todo li{counter-increment:t;position:relative;padding:12px 14px 12px 48px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px;background:var(--bg)}
ol.todo li::before{content:counter(t);position:absolute;left:14px;top:12px;width:22px;height:22px;border-radius:50%;background:var(--surface2);border:1px solid var(--border);text-align:center;line-height:20px;font-size:12px;font-weight:700}
.todo .t{font-weight:650;font-size:14px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.todo .d{color:var(--muted);font-size:12.5px;margin-top:4px}
.eff{font-weight:400;font-size:11px;color:var(--muted);border:1px solid var(--border);border-radius:20px;padding:2px 8px}
a.jump{color:var(--blue);font-size:12px;text-decoration:none;display:inline-block;margin-top:6px}
ul.good,ul.notes{margin:6px 0 0;padding-left:20px;font-size:13px;line-height:1.6}
ul.good li::marker{color:var(--green)}
ul.notes{color:var(--muted);font-size:12px}
.exec details{margin-top:14px}
.pill.s-crit{background:rgba(255,92,92,.15);color:var(--red);border:1px solid var(--red)}
.pill.s-high{background:rgba(240,160,32,.16);color:var(--amber);border:1px solid var(--amber)}
.pill.s-med{background:rgba(88,166,255,.12);color:var(--blue);border:1px solid var(--blue)}
.pill.s-info{background:var(--bg);color:var(--muted);border:1px solid var(--border)}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0 0}
.toolbar button{background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:8px 14px;font:inherit;font-size:12px;cursor:pointer}
.toolbar button:hover{border-color:var(--blue);color:var(--blue)}
.howto{margin-top:12px}
.howto .box{padding:4px 16px 12px;font-size:13px;line-height:1.6}
.howto dl{margin:8px 0 0}
.howto dt{font-weight:650;margin-top:6px}
.howto dd{margin:0;color:var(--muted)}
p.hint{color:var(--muted);font-size:12.5px;margin:-4px 0 12px;max-width:900px;line-height:1.5}
.privacy{margin:22px 0 0;padding:14px 18px;border:1px solid var(--border);border-radius:8px;background:var(--surface);font-size:12px;color:var(--muted);line-height:1.6}
.privacy p{margin:6px 0}
.privacy ul{margin:4px 0 8px;padding-left:20px}
.privacy a,footer a{color:var(--blue)}
.invbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:0 0 12px;position:sticky;top:0;z-index:5;background:var(--bg);padding:8px 0}
.invbar input[type=search]{flex:1 1 340px;min-width:220px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:9px 12px;font:inherit;font-size:13px}
.invbar input[type=search]:focus{outline:none;border-color:var(--blue)}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--border);border-radius:20px;padding:4px 10px;font-size:12px;cursor:pointer;background:var(--surface)}
.chip input{margin:0}
.invbar button{background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:8px 12px;font:inherit;font-size:12px;cursor:pointer}
.invbar button:hover{border-color:var(--blue);color:var(--blue)}
#invcount{font-size:12px}
@media print{.noprint{display:none !important} body.print-exec .wrap > :not(header):not(.exec){display:none !important}}
@media (max-width:700px){.sev-grid{grid-template-columns:repeat(2,1fr)}}
@media print{
:root{--bg:#fff;--surface:#fff;--surface2:#f3f4f6;--border:#c9ced6;--text:#111;--muted:#555;--red:#c62828;--amber:#b26a00;--green:#1b7f35;--blue:#0b5cad}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{background:#fff}
.exec{break-after:page;border-width:2px}
a.jump{display:none}
}
/* Sprache: der Report enthält DE und EN, html[data-lang] blendet eine Sprache aus */
html[data-lang=de] .l-en, html[data-lang=en] .l-de{display:none !important}
.langbtn{font-weight:650}
table.cve .ptxt .pt-on{display:none}
table.cve.showp .ptxt .pt-on{display:inline}
table.cve.showp .ptxt .pt-off{display:none}
.nvd-attr{font-size:11px}
</style></head><body><div class="wrap">
<header>
<div class="brand">CVEwatch // Asset Scan + KEV Match</div>
<h1>$(Enc $HostName)</h1>
<div class="sub">Scan: $(B $now $nowEn) &nbsp;&middot;&nbsp; $(B 'KEV-Katalog:' 'KEV catalog:') $kevMeta</div>
$incompleteHtml
<div class="status $statusClass">$statusLine &nbsp;&middot;&nbsp; $([int]$totalCVEs) $(B 'CVE-Treffer' 'CVE hits') &nbsp;&middot;&nbsp; $ransomProducts $(B 'mit Ransomware-Bezug' 'with ransomware use')$verStatus$overdueStatus</div>
</header>

$toolbarHtml
$($execHtml.ToString())

<h2 id="sec-kev">$(B 'Aktiv ausgenutzte Schwachstellen auf diesem Gerät' 'Actively exploited vulnerabilities on this device') <span class="count">$(B '(KEV-Abgleich)' '(KEV matching)')</span></h2>
<p class="hint">$(B 'Software auf diesem Gerät, die in Schwachstellen vorkommt, die nachweislich aktiv ausgenutzt werden. „Betroffen“ heißt: Die installierte Version liegt laut NVD im verwundbaren Bereich. „Unklar“ heißt: bitte manuell prüfen.' 'Software on this device that appears in vulnerabilities known to be actively exploited. "Affected" means: according to the NVD the installed version is in the vulnerable range. "Unclear" means: please check manually.')</p>
$($matchHtml.ToString())

<h2 id="sec-hw">$(B 'System & Hardware' 'System & hardware')</h2>
<p class="hint">$(B 'Basisdaten des Geräts als Referenz für Inventar und Audit.' 'Basic device data as a reference for inventory and audit.')</p>
<div class="grid">
<div class="kv"><div class="k">$(B 'Betriebssystem' 'Operating system')</div><div class="v">$(Enc $OSDisplay)</div></div>
<div class="kv"><div class="k">CPU</div><div class="v">$(Enc $CPU)</div></div>
<div class="kv"><div class="k">GPU</div><div class="v">$(Enc $GPU)</div></div>
<div class="kv"><div class="k">RAM</div><div class="v">$(Enc $RAM)</div></div>
<div class="kv"><div class="k">Mainboard</div><div class="v">$(Enc $MB)</div></div>
<div class="kv"><div class="k">System</div><div class="v">$(Enc $SystemModel)</div></div>
<div class="kv"><div class="k">BIOS</div><div class="v">$(Enc $BIOS)</div></div>
<div class="kv"><div class="k">$(B 'Seriennummer' 'Serial number')</div><div class="v">$(V $Serial)</div></div>
<div class="kv"><div class="k">$(B 'Benutzer' 'User')</div><div class="v">$(Enc $env:USERNAME)</div></div>
<div class="kv"><div class="k">$(B 'Defender-Signatur' 'Defender signature')</div><div class="v">$(V $DefState)</div></div>
<div class="kv"><div class="k">Firewall</div><div class="v">$(V $FwState)</div></div>
</div>

<h2 id="sec-storage">$(B 'Massenspeicher' 'Storage') <span class="count">($($Storage.Count) $(B 'Datenträger' 'disks'))</span></h2>
<p class="hint">$(B 'Zustand und Belegung aller Datenträger inklusive USB. Volle oder defekte Laufwerke gefährden Daten und Betrieb, unverschlüsselte Wechselmedien sind ein Datenschutzrisiko.' 'Health and usage of all disks including USB. Full or defective drives endanger data and operations, unencrypted removable media are a data protection risk.')</p>
$($storageHtml.ToString())

<h2 id="sec-net">$(B 'Netzwerk' 'Network')</h2>
<p class="hint">$(B 'Netzwerkkonfiguration des Geräts. Öffentliche IP, Latenz und Download-Geschwindigkeit erscheinen nur, wenn die jeweilige Option vor dem Scan aktiviert wurde.' 'Network configuration of the device. Public IP, latency and download speed only appear if the respective option was enabled before the scan.')</p>
<div class="grid">
<div class="kv"><div class="k">$(B 'Lokale IP' 'Local IP') ($(V $Kind))</div><div class="v">$(Enc $LocalIP)</div></div>
<div class="kv"><div class="k">MAC</div><div class="v">$(Enc $LocalMAC)</div></div>
<div class="kv"><div class="k">Gateway</div><div class="v">$(Enc $Gateway) &nbsp;$(V $GwMs)</div></div>
<div class="kv"><div class="k">$(B 'Ausgehende IP' 'Outgoing IP')</div><div class="v">$(V $OutIP)</div></div>
<div class="kv"><div class="k">DNS</div><div class="v">$(Enc $LocalDNS)</div></div>
<div class="kv"><div class="k">$(B 'Internet-Latenz' 'Internet latency')</div><div class="v">$(V $PingMs)</div></div>
$speedTile
</div>

<h2 id="sec-posture">$(B 'Sicherheits-Posture' 'Security posture') <span class="count">$(B '(Patch- & Härtungsstatus)' '(patch & hardening status)')</span></h2>
<p class="hint">$(B 'Patch- und Härtungsstatus des Systems. Rot = Risiko, Orange = Hinweis zur Prüfung.' 'Patch and hardening status of the system. Red = risk, orange = notice to check.')</p>
<div class="grid">
$($postureHtml.ToString())
</div>
<h3 class="subhead" id="sec-defender">Microsoft Defender</h3>
<p class="hint">$(B 'Zustand des Windows-Virenschutzes: Versionen, Schutzfunktionen und Aktualität der Signaturen.' 'Status of the Windows antivirus: versions, protection features and how current the signatures are.')</p>
<div class="grid">
$($defenderHtml.ToString())
</div>
<div style="margin-top:12px">
$($portsHtml.ToString())
</div>

<h2>$(B 'Vollständiges Inventar' 'Full inventory') <span class="count">($($invClean.Count) $(B 'Einträge' 'entries'))</span></h2>
<p class="hint">$(B 'Alle erfassten Programme, Dienste und Treiber. Das ist die Grundlage des KEV-Abgleichs.' 'All recorded programs, services and drivers. This is the basis of the KEV matching.')</p>
$($invBar.ToString())
$($invHtml.ToString())
<div id="invnone" class="muted" style="display:none;padding:10px 2px">$(B 'Keine Einträge gefunden. Suchbegriff kürzen oder Filter zurücksetzen.' 'No entries found. Shorten the search term or reset the filter.')</div>

<div class="note">
<div class="l-de">
<b>Wie dieser Abgleich funktioniert &mdash; und was er NICHT sagt.</b><br>
Der Abgleich erfolgt auf <b>Produkt- und Herstellername</b>, weil der KEV-Katalog keine
maschinenlesbaren Versionsbereiche liefert. Ein Treffer bedeutet: <b>dieses Produkt taucht in
einer aktiv ausgenutzten Schwachstelle auf</b> &mdash; nicht zwingend, dass deine <b>installierte
Version</b> verwundbar ist. Prüfe pro CVE (Link zur NVD) den betroffenen Versionsbereich und ob
du bereits gepatcht bist. Die <b>Match-Konfidenz</b> zeigt, wie sicher die Zuordnung ist, und die
<b>Basis</b> darunter, worauf sie beruht: <b>Produkt + Hersteller</b> (KEV-Produkt <i>und</i>
-Hersteller passen zum Gerät &mdash; hohe Sicherheit) oder <b>Produktname</b> (nur der Produktname
passt). Kurze/mehrdeutige Produktnamen (z.B. 7-Zip, VLC) werden bewusst nur akzeptiert, wenn auch
der Hersteller passt. Der orange Punkt / das Label markiert CVEs mit bekanntem
<b>Ransomware-Einsatz</b> &mdash; die zuerst prüfen.<br><br>
<b>CISA-Frist &amp; Dringlichkeit.</b> Die <b>Frist</b> ist das offizielle CISA-Fälligkeitsdatum
(BOD 22-01) &mdash; für US-Behörden verbindlich, für alle anderen ein starkes Dringlichkeits-Signal.
<span style="color:var(--red);font-weight:600">Rot = überfällig</span>,
<span style="color:var(--amber)">orange = fällig in &le; 14 Tagen</span>. Produkte und CVEs sind nach
Dringlichkeit sortiert: <b>Ransomware &rarr; Frist (überfällig zuerst) &rarr; Versions-Verdikt
(betroffen &gt; unklar &gt; vermutlich gepatcht) &rarr; Konfidenz</b>. Bewusst <i>ohne</i> EPSS: für
KEV-Einträge ist die Ausnutzung bereits bestätigt &mdash; eine Ausnutzungs-<i>Wahrscheinlichkeit</i>
wäre daneben redundant. Was zwischen zwei bestätigten Exploits entscheidet, sind Ransomware-Bezug,
Frist und ob deine Version betroffen ist &mdash; alles aus offiziellen Erstquellen (CISA + NVD).<br><br>
<b>Versionsabgleich (NVD).</b> Wo eine installierte Version vorliegt, zieht CVEwatch für die
gematchten CVEs die Versionsbereiche aus der NVD (CPE) und vergleicht sie: <b>Version betroffen</b>
(deine Version liegt im verwundbaren Bereich), <b>Vermutlich gepatcht</b> (außerhalb aller
bekannten Bereiche) oder <b>Version unklar</b> (kein passendes CPE, nicht vergleichbare
Versionszeichenfolge, oder NVD nicht erreichbar). Das ist eine gute Heuristik, aber kein Ersatz
für die manuelle Prüfung: CPE-Daten sind nicht immer vollständig, und Hersteller-Versionsschemata
weichen ab. Dienste (ohne Versionsangabe) werden bewusst nicht gematcht, um Fehlalarme zu vermeiden.
KEV-Einträge zu Windows selbst werden nicht per Name, sondern über den installierten Build gegen die NVD geprüft.<br><br>
<b>Download-Speedtest.</b> Gemessen wird der Durchsatz beim Laden einer 10-MB-Testdatei von crusadersoft.com
(ohne DNS-/TLS-Aufbau, direkt im Speicher, ohne Schreiben auf die Platte). Das ist eine <b>Momentaufnahme</b>:
WLAN, Tageszeit und Gegenstelle beeinflussen den Wert, und bei sehr schnellen Anschlüssen (grob ab 300 Mbit/s)
ist eine 10-MB-Datei zu klein, um die Leitung voll auszulasten (TCP-Anlaufphase) &mdash; der Wert ist dann ein Mindestwert.
</div>
<div class="l-en">
<b>How this matching works &mdash; and what it does NOT say.</b><br>
Matching is based on <b>product and vendor name</b>, because the KEV catalog provides no
machine-readable version ranges. A hit means: <b>this product appears in an actively exploited
vulnerability</b> &mdash; not necessarily that your <b>installed version</b> is vulnerable. For each
CVE (link to the NVD), check the affected version range and whether you are already patched. The
<b>match confidence</b> shows how reliable the match is, and the <b>basis</b> below it what it is
based on: <b>product + vendor</b> (KEV product <i>and</i> vendor match the device &mdash; high
confidence) or <b>product name</b> (only the product name matches). Short/ambiguous product names
(e.g. 7-Zip, VLC) are deliberately only accepted if the vendor also matches. The orange dot / label
marks CVEs with known <b>ransomware use</b> &mdash; check those first.<br><br>
<b>CISA due date &amp; urgency.</b> The <b>due date</b> is the official CISA due date
(BOD 22-01) &mdash; binding for US federal agencies, a strong urgency signal for everyone else.
<span style="color:var(--red);font-weight:600">Red = overdue</span>,
<span style="color:var(--amber)">orange = due in &le; 14 days</span>. Products and CVEs are sorted by
urgency: <b>ransomware &rarr; due date (overdue first) &rarr; version verdict
(affected &gt; unclear &gt; probably patched) &rarr; confidence</b>. Deliberately <i>without</i> EPSS: for
KEV entries exploitation is already confirmed &mdash; an exploitation <i>probability</i> would be
redundant. What decides between two confirmed exploits is ransomware use, the due date and whether
your version is affected &mdash; all from official primary sources (CISA + NVD).<br><br>
<b>Version check (NVD).</b> Where an installed version is available, CVEwatch pulls the version
ranges for the matched CVEs from the NVD (CPE) and compares them: <b>version affected</b> (your
version is in the vulnerable range), <b>probably patched</b> (outside all known ranges) or
<b>version unclear</b> (no matching CPE, non-comparable version string, or NVD unreachable). This is
a good heuristic, but no substitute for a manual check: CPE data is not always complete, and vendor
version schemes differ. Services (without version information) are deliberately not matched to avoid
false alarms. KEV entries for Windows itself are not checked by name, but via the installed build against the NVD.<br><br>
<b>Download speed test.</b> It measures the throughput when downloading a 10 MB test file from crusadersoft.com
(without DNS/TLS setup, directly in memory, without writing to disk). This is a <b>snapshot</b>:
Wi-Fi, time of day and the server influence the value, and on very fast connections (roughly above 300 Mbit/s)
a 10 MB file is too small to fully saturate the line (TCP slow start) &mdash; the value is then a minimum.
</div>
</div>
$($privacyHtml.ToString())
<footer>CVEwatch Asset Scan v$ScriptVersion &middot; $(B $now $nowEn) &middot; $(B 'CSV/JSON/LOG unter' 'CSV/JSON/LOG in') $(Enc $HostDir) &middot; <a href="$PrivacyUrl" target="_blank" rel="noopener noreferrer">$(B 'Datenschutz' 'Privacy')</a></footer>
$scriptHtml
</div></body></html>
"@)

$sb.ToString() | Out-File $ReportPath -Encoding UTF8

#endregion

#region ============================ HOST-LOG + ÖFFNEN ======================

# Host-Log in der Sprache des Laufs
@"
$OSDisplay
$CPU
$GPU
$MB
$SystemModel
$BIOS
$env:USERNAME
Defender: $(LT $DefState)
Firewall: $(LT $FwState)
IP: $LocalIP ($(LT $Kind))  MAC: $LocalMAC
Gateway: $Gateway ($(LT $GwMs))
Out: $(LT $OutIP)  Ping: $(LT $PingMs)
Download: $(LT $SpeedText)
$(G 'Defender-Produkt' 'Defender product'): $($DefenderItems['Produktversion'])  Engine: $($DefenderItems['Engine-Version'])  $(G 'Signatur' 'Signature'): $(LT $DefenderItems['Signatur-Version'])
$(G 'Datenträger' 'Disks'): $StorageSummary
DNS: $LocalDNS
Serial: $(LT $Serial)
$(G 'KEV-Treffer' 'KEV hits'): $($matchedArr.Count) $(G 'Produkte' 'products') / $([int]$totalCVEs) CVEs / $ransomProducts Ransomware
"@ | Out-File $LogPath -Encoding UTF8

Write-Host ""
Write-Host "  Report : $ReportPath" -ForegroundColor Green
Write-Host "  CSV    : $CsvPath"     -ForegroundColor DarkGray
Write-Host "  Matches: $MatchPath"   -ForegroundColor DarkGray
Write-Host ""
Write-Host "CVEWATCH_REPORT=$ReportPath"   # maschinenlesbarer Marker (u.a. für die GUI)

# --- Maschinenlesbare Zusammenfassung + Exit-Code (für Automatisierung/geplante Tasks) ---
# Exit-Codes:  0 = sauber/übersprungen | 2 = KEV-Treffer mit offener Version | 3 = überfällige CISA-Frist | 4 = Version betroffen
#              (Treffer, die laut NVD "Vermutlich gepatcht" sind, zählen nicht für 2/3 und nicht für die Ransomware-Warnung)
#              1 = vom Nutzer vor dem Scan abgebrochen (Konsole ohne Administratorrechte)
#              5 = Administratorrechte fehlen und -RequireAdmin ist gesetzt (Scan nicht gestartet)
$exitCode = 0
if ($KevSkipped)                 { $exitCode = 0 }
elseif ($affectedCount -gt 0)    { $exitCode = 4 }
elseif ($overdueProducts -gt 0)  { $exitCode = 3 }
elseif ($openProducts.Count -gt 0) { $exitCode = 2 }

$summary = "CVEWATCH_SUMMARY host=$HostName kev_products=$($matchedArr.Count) open=$($openProducts.Count) nvd_skipped=$nvdSkipped cve_hits=$([int]$totalCVEs) affected=$affectedCount overdue=$overdueProducts ransomware=$ransomProducts new=$newHits admin=$(if ("$AdminState" -match '^ja') { 1 } else { 0 }) exit=$exitCode"
Write-Host ""
Write-Host $summary -ForegroundColor Cyan

# Status-Datei (GUI): Report-Pfad, Summary, Fertig-Marker
if ($StatusFile) {
    try {
        "reportpath`t$ReportPath" | Out-File -FilePath $StatusFile -Append -Encoding UTF8
        "summary`t$summary"       | Out-File -FilePath $StatusFile -Append -Encoding UTF8
        "done`tFertig"            | Out-File -FilePath $StatusFile -Append -Encoding UTF8
    } catch {}
}

# Report oeffnen (letzter Schritt vor Exit; die GUI setzt -NoOpen und oeffnet selbst)
if (-not $NoOpen) {
    try { Start-Process $ReportPath } catch { Write-Host ((G "Report manuell öffnen: " "Open report manually: ") + $ReportPath) -ForegroundColor Yellow }
}

#endregion

exit $exitCode