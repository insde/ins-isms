# Branchentipps Managed Hosting & SaaS: Kritische Schwachstellen, Notfall-Patches & Incidents im `ins-isms`

Dieser Text richtet sich speziell an **Managed Hosting Provider, IT-Dienstleister und Software-Betreiber**, die Kundensysteme oder Anwendungssoftware aktiv pflegen. 

In der Praxis werden heute regelmäßig kritische Zero-Day-Lücken bekannt (z. B. *Log4Shell*, *PHP2Shell*, *Java2Shell*,  *XZ*, *OpenSSL* etc. etc.), die sofortiges Handeln erfordern. Für den ISB stellt sich dann im Audit oft die Frage: *„Wo dokumentiere ich was – und wann wird ein Notfall-Patch zum meldepflichtigen Sicherheitsvorfall?“*

---

## 1. Die wichtigste Grundregel: Schwachstelle ≠ Sicherheitsvorfall

Ein häufiger Stolperstein in Audits ist die Vermischung von **Schwachstellenmanagement (`A.8.8`)** und **Incident Management (`A.5.24`–`A.5.26`)**.

* **Kein Incident:** Das reine Bekanntwerden einer kritischen Lücke, ein positiv angeschlagener Schwachstellen-Scanner auf einem eigenen System oder automatisiert geblockte Angriffsversuche aus dem Internet (z. B. durch WAF/Firewall) sind **keine** Sicherheitsvorfälle. Sie gehören in das reguläre bzw. beschleunigte Patch- und Change-Management (Ticketsystem).
* **Wann es ein Incident wird:** Ein Eintrag unter `Incidents` in `ins-isms` ist erst dann zwingend erforderlich, wenn:
  1. **Ausnutzung nachgewiesen oder wahrscheinlich ist:** Auf einem Kunden- oder Trägersystem werden sogenannte *Indicators of Compromise (IoCs)* gefunden (z. B. verdächtige Webshells, unbekannte Prozesse, ungewöhnliche ausgehende Verbindungen).
  2. **Ungeplanter Schaden entsteht:** Das Einspielen eines Notfall-Patches führt zu einem ungeplanten Ausfall von Kundensystemen oder Datenverlust.
  3. **Datenabfluss droht:** Unbefugte hatten Zugriff auf Kundendaten (`C3`/`C4`) – hier greifen zusätzlich DSGVO- (72-Stunden-Frist) und ggf. NIS2-Meldepflichten.

---

## 2. Pragmatischer Ablauf bei kritischen Zero-Days (Playbook)

Damit Sie im Audit zeigen können, dass Hektik im Betrieb trotzdem systematisch abläuft („Systematik statt Zufall“), empfiehlt sich folgender 4-Schritte-Standardprozess:

1. **Betroffenheit prüfen (Asset-Abgleich):**
   - Prüfen Sie anhand Ihres Inventars / Ihrer CMDB, welche Kundenumgebungen und eigenen Systeme die betroffene Software-Version (z. B. PHP, Java, Webserver, Datenbank) einsetzen.
2. **Notfall-Change & Workaround ausrollen:**
   - Dokumentieren Sie das Einspielen des Patches oder das Aktivieren von Schutzregeln (z. B. WAF-Rule) als *Emergency Change* in Ihrem regulären Ticketsystem.
3. **Kompromittierung ausschließen (IoC-Check):**
   - *Wichtiger Audit-Nachweis:* Prüfen Sie vor oder direkt nach dem Patchen die Logfiles und Dateisysteme der betroffenen Server auf Spuren einer bereits erfolgten Ausnutzung. Halten Sie das Ergebnis („Keine IoCs gefunden“) kurz im Ticket fest.
4. **Entscheidung über Incident-Eskalation:**
   - **IoC-Check negativ:** Vorgang im Ticketsystem schließen. Kein Eintrag in `ins-isms` unter `Incidents` nötig.
   - **IoC-Check positiv:** Sofort `Incident` in `ins-isms` eröffnen, Kunden gemäß Vertrag/SLAs informieren und Ursachenanalyse inkl. **CAPA** starten.

---

## 3. So bilden Sie das sauber im `ins-isms` ab

Sie müssen nicht jeden einzelnen Kundenserver und nicht jedes Routine-Update in `ins-isms` eintragen. Nutzen Sie die bestehenden Funktionen des Systems gezielt für die **Governance-Ebene**:

### Abschnitt C: System-Assets
* **Keine 500 Einzel-VMs anlegen:** Fassen Sie gleichartige Infrastruktur in logische Gruppen zusammen (z. B. `SYS-010: Managed Webhosting Cluster (Linux/PHP)`, `SYS-011: Kunden-Applikationsserver (Java/Tomcat)`, `SYS-012: Zentrales Patch- & Konfigurationsmanagement`).
* **Kunden-Schutzstufe vererben:** Verknüpfen Sie diese Plattform-Assets mit dem Informationswert *„Kundendaten & gehostete Anwendungsdaten“* (`C3` bzw. `C4`). Durch das Maximumprinzip erhalten die Hosting-Cluster automatisch die korrekte hohe Schutzstufe.

### Abschnitt D: Richtlinien & Runbooks (`Dokumente`)
* **Wiki statt Doppelpflege:** Wenn Sie bereits ein technisches Runbook für *„Notfall-Patching & Zero-Day-Reaktion“* in Confluence, BookStack oder Ihrem internen Wiki haben, tippen Sie es nicht ab. Legen Sie es in `ins-isms` als Dokument mit `source_type = external_link` an und verweisen Sie auf die Wiki-URL.
* **Zuständigkeiten klären:** Definieren Sie in Ihrer Betriebsleitlinie (`POL-002` oder einer eigenen *Patch- & Schwachstellen-Richtlinie*) verbindliche Reaktionszeiten (z. B. *„Kritische Schwachstellen mit CVSS ≥ 9.0 und aktiver Ausnutzung werden innerhalb von 24 Stunden gepatcht oder durch Workarounds abgesichert“*) sowie die Abgrenzung, welche Software-Schicht der Hoster und welche der Kunde verantwortet.

### Abschnitt E: SoA & Nachweise
Für Hosting-Anbieter schaut der Auditor besonders genau auf folgende ISO-27001-Controls:
* **`A.8.8` (Management technischer Schwachstellen):** Verlinken Sie per Deep-Link auf Ihre Patch-Regelung und hinterlegen Sie als Datei-Nachweis (`file`) z. B. einen anonymisierten Export/Screenshot eines abgeschlossenen Emergency-Patch-Tickets (inkl. dokumentiertem IoC-Check).
* **`A.8.19` (Installation von Software auf Betriebssystemen) & `A.8.32` (Change Management):** Belegen Sie durch Verweis auf Ihr Ticketsystem, wie Notfall-Changes freigegeben und nachvollziehbar ausgerollt werden.
* **`A.5.24` / `A.5.25` (Incident Management):** Hinterlegen Sie Ihre Bewertungsmatrix, ab wann ein Sicherheitsereignis zum Incident eskaliert wird.

### Schritt G: Compliance-Kalender (`Actions`)
* Ergänzen Sie die Standard-Serienaufgaben um eine **quartalsweise Stichprobenprüfung (`quarterly`)**: *„Abgleich Software-Inventar (PHP/Java/OS-Versionen) aller Kundenumgebungen auf veraltete/EOL-Versionen und Prüfung der letzten Emergency-Patch-Tickets“*.

---

## 4. Audit-Tipp: Was Prüfer bei Hostern besonders gern fragen

* **„Wie stellen Sie sicher, dass Sie kein Kundensystem vergessen?“** → Zeigen Sie Ihr zentrales Monitoring, Asset-Inventar oder Konfigurationsmanagement (z. B. Ansible, Puppet, etc.) als Nachweis zu `A.5.9` und `A.8.8`.
* **„Wo endet Ihre Pflicht und wo beginnt die Pflicht des Kunden?“** → Halten Sie eine klare **Verantwortlichkeitsmatrix (RACI)** bereit (z. B. *OS & PHP-Runtime = Hoster; individueller Kunden-Code / CMS-Plugins = Kunde, sofern kein Full-Managed-Vertrag besteht*).
* **„Zeigen Sie mir einen Fall, bei dem es schnell gehen musste.“** → Halten Sie 1–2 gut dokumentierte Tickets (z. B. zur letzten großen PHP- oder OpenSSL-Lücke) griffbereit, an denen man *Erkennung → Inventarabgleich → Patch → IoC-Check → Kundeninfo* lückenlos nachvollziehen kann.
