Was macht CVEwatch?
CVEwatch inventarisiert dein Windows-Gerät (Hardware, installierte Software, Treiber, Dienste) und gleicht die Software mit dem CISA-KEV-Katalog ab - das sind Schwachstellen, die NACHWEISLICH aktiv ausgenutzt werden. Anschließend prüft es per NVD, ob deine installierte Version tatsächlich im verwundbaren Bereich liegt. Ergebnis ist ein nach Dringlichkeit sortierter HTML-Report. Alles läuft lokal auf dem Gerät.

Der Ablauf (Stufen links)
1. System + Hardware   2. Sicherheits-Posture   3. Netzwerk   4. Software-Inventar   5. KEV-Katalog laden   6. KEV-Abgleich   7. NVD-Versionsabgleich   8. HTML-Report. Der Fortschritt wird links live angezeigt; der Scan läuft als eigener Prozess, das Fenster bleibt bedienbar.

Optionen
• KEV-Abgleich: aus = nur Geräte-Inventar und Sicherheits-Posture (kein Schwachstellen-Abgleich).
• NVD-Versionsabgleich: prüft, ob deine Version betroffen ist. Aus = nur "Produkt ist in KEV".
• NVD-API-Key (optional, kostenlos bei nvd.nist.gov): hebt das Limit von 5 auf 50 Anfragen/30s - der Versionscheck wird schnell und zuverlässig.
• Cache verwenden: nimmt KEV/NVD aus dem lokalen Zwischenspeicher statt frisch zu laden (schneller/offline).
• Verbindungen nach außen (alle standardmäßig AUS, einzeln schaltbar): Öffentliche IP (Anfrage an api.ipify.org / ifconfig.me), Internet-Latenz (Ping an www.google.de / www.devicentra.de), Download-Speedtest (10 MB von crusadersoft.com). Kommandozeile: -PublicIP, -Latency, -SpeedTest oder -External für alle drei.

Aktualität & Cache
Standard ist bewusst: KEV UND NVD werden bei JEDEM Lauf frisch geladen - denn jederzeit kann eine neue, gerade ausgenutzte CVE dazukommen. "Cache verwenden" ist die schnelle bzw. offline-Option; ansonsten dient der Cache nur als Ausfall-Netz, falls CISA/NVD kurz nicht erreichbar sind.

Den Report lesen
Produkte und CVEs sind nach echter Dringlichkeit sortiert: Ransomware-Bezug -> CISA-Frist (überfällig zuerst) -> Versions-Verdikt (betroffen > unklar > vermutlich gepatcht) -> Match-Konfidenz. Farben: rot = betroffen/überfällig, orange = fällig bald/Ransomware, grün = vermutlich gepatcht. Ein grünes NEU markiert Treffer, die seit dem letzten Lauf dazugekommen sind. Konfidenz + Basis zeigen, wie sicher die Zuordnung ist (Produkt+Hersteller vs. nur Produktname). Bewusst OHNE EPSS - bei KEV ist die Ausnutzung bereits bestätigt, eine Wahrscheinlichkeit wäre daneben redundant.

Drucken & Weitergeben
Der Bericht beginnt mit einer Management-Übersicht (Ampel, Befunde nach Schweregrad, die wichtigsten Maßnahmen). Oben im Bericht gibt es Knöpfe: nur die Übersicht oder den ganzen Bericht drucken - im Druckdialog des Browsers dann "Als PDF speichern" wählen. Der Bericht enthält personenbezogene Daten (Hostname, Benutzerkonten, IP/MAC, installierte Software): nur an Berechtigte weitergeben und nach Gebrauch löschen.

Sicherheits-Posture
Zusätzlich zum Schwachstellen-Abgleich: Patch-Stand, ausstehender Neustart, Secure Boot, BitLocker, TPM, RDP, SMBv1, UAC, registrierte Antivirus-Produkte, lokale Administratoren, Gast-Konto, Autologon, SMB-Freigaben, LSA-Schutz, Virtualisierungsbasierte Sicherheit/HVCI, Credential Guard, NTLM-Level, Geräte-Einbindung (Entra ID/Domäne) und offene (lauschende) Ports. Dazu ein eigener Defender-Block (Produkt-, Engine- und Signaturversion, Echtzeit-, Manipulations-, Cloud-, PUA- und Netzwerkschutz, ASR-Regeln, Ausschlüsse, letzte Scans). Der Massenspeicher-Abschnitt zeigt alle Datenträger (HDD/SSD/NVMe/USB) mit Zustand, Belegung und BitLocker-Status. Riskante Zustände werden rot, Hinweise orange hervorgehoben.

Exporte & Automatisierung
Jeder Lauf erzeugt mehrere Dateien - vier davon unten im Fenster per Knopf zu öffnen (immer der neueste, nur klickbar wenn vorhanden): Report (HTML, lesbar), Inventar (CSV), Treffer (JSON, maschinenlesbar), Log (Host-Zusammenfassung); dazu eine summary.json mit den Management-Befunden nach Schweregrad. Für Automatisierung gibt das Skript eine CVEWATCH_SUMMARY-Zeile und einen Exit-Code aus: 0 = sauber, 2 = KEV-Treffer, 3 = überfällige Frist, 4 = Version betroffen. Ideal für einen geplanten Task, der nur meldet, wenn es brennt.

Datenschutz & Quellen
Alles läuft lokal; es werden keine Inventardaten übertragen. Standardmäßig gehen nur zwei Abrufe nach außen: der KEV-Katalog (CISA, cisa.gov) und pro Treffer die CVE-Details (NIST NVD, nvd.nist.gov) - dabei werden nur CVE-Kennungen übertragen; CISA und NIST sehen deine IP-Adresse. Öffentliche IP, Latenzmessung und Speedtest sind Opt-in (Standard: aus): Die IP-Abfrage geht an api.ipify.org bzw. ifconfig.me, die Latenzmessung pingt www.google.de bzw. www.devicentra.de, der Speedtest lädt 10 MB von crusadersoft.com (es wird nichts hochgeladen); die jeweilige Gegenstelle sieht dabei deine IP-Adresse. Keine Telemetrie, keine Weitergabe deiner Softwareliste. Bericht und Exporte bleiben auf diesem Rechner und enthalten personenbezogene Daten (z. B. Hostname, Benutzerkonten, IP/MAC): nur an Berechtigte weitergeben. Datenschutzerklärung: https://crusadersoft.com/#datenschutz

Enterprise
Diese kostenlose Version scannt bewusst nur das lokale Gerät. Die Multi-Report-Auswertung (mehrere Berichte zusammenführen), der FleetScan (viele Hosts) und der Netzwerkscan sind der Enterprise-Version vorbehalten - auch aus Sicherheitsgründen, damit nicht jeder beliebige Netzwerke scannen kann. Mehr unter crusadersoft.com und cvewatch.de.

