# Praxistipps & FAQ für ISB: Typische Stolpersteine & pragmatische Antworten

Diese Handreichung richtet sich an IT-Administratoren, IT-Leiter und Quereinsteiger bei KMUs, die die Rolle des Informationssicherheitsbeauftragten (ISB) übernommen haben und ein ISMS nach **ISO 27001:2022** (sowie optional **NIS2 / BSIG**) aufbauen wollen ohne sich in zu viel überflüssiger "Konzern-Bürokratie" zu verlieren, die für ein KMU nicht unbedingt notwenig ist und das Vorhaben nur verzögert und aufwändiger macht.

Die Kapitel folgen der Reihenfolge des **ISB-Quickstarts (`isb-quickstart-guide.md`)**.

---

## Vorweg: Was ein ISO-27001-Auditor eigentlich sehen will

Viele denken, sie müssten für die Zertifizierung ein 300-seitiges Handbuch schreiben und jedes Problem bis zum Audittag technisch gelöst haben. **Beides ist falsch.**

Ein Zertifizierungsauditor prüft im Kern nur **vier Dinge**:
1. **Systematik statt Zufall:** Gibt es nachvollziehbare Regeln (Richtlinien, Risikobewertung, Zuständigkeiten)?
2. **Realitätsnähe:** Passt das, was auf dem Papier steht, zu dem, was in der Firma wirklich passiert? *(Man sollte niemals etwas in eine Richtlinie schreiben, was man selbst nicht einhält)*
3. **Gelebte Nachweise:** Können Sie anhand echter Protokolle (Backups, Tickets, Schulungslisten, Lesebestätigungen) zeigen, dass die Regeln angewendet werden?
4. **Kontinuierliche Verbesserung (PDCA):** Wenn etwas noch nicht perfekt ist oder schiefgeht (was ganz normal ist), erkennt man es selbst, plant man eine Maßnahme und prüfen später, ob sie gewirkt hat?

**Goldene Regel:** *Lieber 80 % realistisch geregelt und zu 100 % gelebt, als 100 % hochglanzpoliert auf dem Papier und im Alltag ignoriert.*

---

## Auch noch Vorweg: Kann ich mit dem ins-isms die teuren ISO-Berater ersetzen? Ich will kein Geld ausgeben. 
- **Kurze Antwort: Ersetzen? Nein!** Der Aufbau und Betrieb eines ISMS braucht Erfahrung, Know-How und Arbeitszeit. Das `ins-isms` versucht zwar durch vorgegebene Methoden und Werkzeuge den Prozess weniger Mühsam zu machen und durch eingebaute Automatiken auch zeitsparend und effizient zu machen, wodurch Sie möglicherweise effizienter arbeiten können, aber das alleine reicht nicht. Sie brauchen auch manchmal (vielleicht sogar "oft") einen Ansprechpartner, der bereits praktische Erfahrung mit einem ISMS hat und den sie um Einschätzungen mit Augenmaß für Ihren speziellen Fall bitten. 
- **Ein Beispiel:** Es ist nicht kosteneffizient (außer Ihre eigene Arbeit hat für Sie keinen Wert) eine ganze Woche über einen Sachverhalt zu grübeln und im Internet zu recherchieren, wenn ein erfahrener Berater Ihnen in 5 Minuten die optimale Antwort geben könnte.

---

## Zu A: Organisationsprofil, Geltungsbereich & Rollen

### „Wie formuliere ich den Geltungsbereich (Scope), ohne mich selbst zu überfordern?“
- **Stolperstein:** Viele schreiben einfach „Die gesamte Firma“ — und merken kurz vor dem Audit, dass die veraltete Produktionshalle in Hintertupfing oder ein unfertiges Nebenprojekt plötzlich mitgeprüft wird. Oder sie grenzen den Scope so eng ein (z. B. nur den Serverraum), dass der Auditor ihn als unglaubwürdig ablehnt.
- **Pragmatische Lösung:** Beschreiben Sie klar **Standort(e), Kernleistung und unterstützende Bereiche**.
  - *Gutes KMU-Beispiel:* „Entwicklung, Betrieb und Support unserer Softwarelösungen am Standort Musterstadt inklusive Verwaltung, Vertrieb und zugehöriger IT-Infrastruktur.“
  - Falls ein Nebengebäude oder eine Tochtergesellschaft bewusst draußen bleibt: Begründen Sie kurz warum (eigene IT, keine Verbindung zu Kundendaten).

### „Ist die Geschäftsführung eine eigene Organisationseinheit?“
- **Antwort:** **Ja.** Auch in einer 12-Mann-GmbH sollte „Geschäftsführung“ (oder „Unternehmensleitung“) als eigene Einheit angelegt werden.
- **Warum:** ISO 27001 Kapitel 5 verlangt sichtbare Verantwortung der obersten Leitung. Strategische Richtlinien (`POL-001`), die Freigabe der Management-Bewertung und die Akzeptanz hoher Risiken hängen organisatorisch dort.

### „Wir haben nur eine Teilzeitkraft für vorbereitende Buchhaltung und einen externen Steuerberater. Brauche ich eine Einheit ‚Buchhaltung‘?“
- **Antwort:** **Nein, fassen Sie kleine Querschnittsfunktionen zusammen.**
- **Pragmatische Lösung:** Legen Sie eine gemeinsame Einheit **„Verwaltung, Finanzen & HR“** an. Der externe Steuerberater oder das Lohnbüro ist **keine** interne Organisationseinheit, sondern wird später in Schritt 3 als System-Asset vom Typ **`Dienstleister / Lieferant`** erfasst.

### „Wie viele Organisationseinheiten sind für einen KMU ideal?“
- **Daumenregel (10–150 Mitarbeiter):** **4 bis 7 Einheiten** reichen völlig aus:
  1. *Geschäftsführung*
  2. *IT & Infrastruktur*
  3. *Softwareentwicklung* bzw. *Produktion / Technik*
  4. *Vertrieb & Kundenservice*
  5. *Verwaltung, Finanzen & HR*
- **Warum nicht 20 Einheiten?** Jede Einheit braucht einen Verantwortlichen (`owner`). Zu viele Einheiten erzeugen nur Pflegeaufwand bei Zuständigkeiten.

### „Ich bin gleichzeitig IT-Admin und ISB — welche Rolle nehme ich in `ins-isms`?“
- **Antwort:** Trennen Sie die Konten technisch, auch wenn dahinter dieselbe Person steht:
  - Nutzen Sie ein Konto mit Rolle **`iso`** für Ihre tägliche ISB-Arbeit (Richtlinien, Risiken, SoA, Audits).
  - Halten Sie ein separates, zusätzliches **`admin`**-Konto nur für Systemkonfiguration und Benutzerverwaltung vor.
  - **Audit-Vorteil:** Das beweist sofort gelebte Funktionstrennung (*Segregation of Duties*) und sorgt im Audit-Log für klare Nachvollziehbarkeit.

---

## Zu B: Schutzstufen & Informationswerte

### „Muss ich jeden einzelnen Ordner auf dem Netzlaufwerk als Informationswert anlegen?“
- **Antwort:** **Auf keinen Fall.** Wenn Sie 80 Ordner anlegen, pflegen Sie das Inventar nach zwei Monaten nicht mehr.
- **Pragmatische Lösung:** Denken Sie in **Datenkategorien mit gleichem Schutzbedarf und gleicher Aufbewahrungsfrist**. Für ein typisches KMU reichen **8 bis 15 Informationswerte** völlig aus:
  - *Personalakten & Bewerberdaten* (`C3`, Aufbewahrung: gesetzlich / nach Austritt)
  - *Finanz-, Lohn- & Buchhaltungsdaten* (`C3`, Aufbewahrung: 10 Jahre nach HGB/AO)
  - *Kundenstammdaten & Verträge* (`C3`, Aufbewahrung: Vertragslaufzeit + 10 Jahre)
  - *Quellcode / Konstruktionspläne / Kern-IP* (`C4`, Aufbewahrung: unbefristet / Produktlebenszyklus)
  - *Passwörter, API-Keys & kryptografische Schlüssel* (`C4`, Aufbewahrung: bis Widerruf/Rotation)
  - *Interne Projektdokumentation & Wikis* (`C2`, Aufbewahrung: 5 Jahre)
  - *E-Mail-Kommunikation (geschäftlich)* (`C2`/`C3`, Aufbewahrung: 6–10 Jahre nach GoBD)
  - *Öffentliche Website- & Marketinginhalte* (`C1`, Aufbewahrung: bis Aktualisierung)

### „Was ist der Unterschied zwischen Vertraulichkeit, Integrität und Verfügbarkeit (CIA)?“
- **Vertraulichkeit (C):** *Wie schlimm ist es, wenn Unbefugte die Daten lesen?* (z. B. Gehaltslisten, Kundendaten → **Hoch / Sehr hoch**).
- **Integrität (I):** *Wie schlimm ist es, wenn Daten unbemerkt verfälscht werden?* (z. B. Buchhaltungsdaten, Quellcode, Stücklisten → **Hoch / Sehr hoch**).
- **Verfügbarkeit (A):** *Wie schlimm ist es, wenn die Daten 1–2 Tage nicht erreichbar sind?* (z. B. Produktiv-ERP → **Hoch**, alte Marketing-Broschüren → **Normal**).

### „Muss ich Mitarbeiter zwingen, jede E-Mail und jedes Word-Dokument mit ‚C2 – Intern‘ zu beschriften?“
- **Antwort:** **Nein — nutzen Sie das Standard-Prinzip (Default-Regel).**
- **Pragmatische Lösung:** Legen Sie in Ihrer Handling-Matrix (`C2 Intern`) fest: *„Alle internen Geschäftsdokumente ohne besondere Kennzeichnung gelten automatisch als C2 (Intern). Eine explizite Kennzeichnung in Kopfzeile oder Dateinamen ist nur für C3 (Vertraulich) und C4 (Streng vertraulich) Pflicht.“* Das spart enorm viel Reibung im Alltag und ist zu 100 % ISO-A.5.13-konform.

---

## Zu C: IT-Systeme, Standorte & kritische Lieferanten

### „Muss ich wirklich jeden einzelnen Laptop, Monitor, Server und Switch eintragen?“
- **Antwort:** **Nein.** `ins-isms` ist ein ISMS-Register und keine Hardware-CMDB mit Seriennummern.
- **Pragmatische Lösung:** Erfassen Sie **logische Gruppen** für gleichartige Hardware:
  - *1 Eintrag* `Standard-Notebooks Windows 11` (`Endgerät (Gruppe)`) statt 45 einzelne Laptops.
  - *1 Eintrag* `Büro-Netzwerk & WLAN` (`Netzwerk`) statt 12 einzelne Access Points.
  - Einzeln erfassen Sie nur die **geschäftskritischen Kernsysteme** (z. B. *ERP-System*, *Haupt-Firewall*, *Backup-Server*, *Microsoft 365*).

### „Wann nehme ich ‚Cloud-Dienst‘ und wann ‚Dienstleister / Lieferant‘?“
- **Faustregel:**
  - **`Cloud-Dienst`:** Sie nutzen direkt eine technische SaaS-/PaaS-Plattform, auf der Firmendaten liegen (z. B. *Microsoft 365*, *DATEV Unternehmen online*, *Nextcloud*, *GitHub*).
  - **`Dienstleister / Lieferant`:** Ein externes Unternehmen erbringt eine Dienstleistung oder betreibt Infrastruktur für Sie (z. B. *externes IT-Systemhaus*, *Rechenzentrums-Colocation*, *Steuerberater*, *Aktenvernichtungsdienstleister*).
- **Tipp:** Verknüpfen Sie kritische Dienstleister (z. B. IT-Systemhaus mit Admin-Zugriff oder Steuerberater) mit den betroffenen `C3`/`C4`-Informationswerten. Durch das **Maximumprinzip** erbt der Dienstleister automatisch die richtige Schutzstufe.

### „Wann brauche ich ‚Standort / Raum‘ und ‚Maschine / OT-Anlage‘?“
- **`Standort / Raum`:** Immer sinnvoll für Ihren **Hauptstandort** sowie besonders geschützte Bereiche wie **Serverraum**, **Archivraum** oder **Fertigungshalle** (deckt ISO 27001 Anhang A.7 physische Sicherheit ab).
- **`Maschine / OT-Anlage`:** Nur relevant, wenn Sie Fertigungs-, Werkstatt-, Labor- oder Medizintechnik-Anlagen betreiben, die am Netzwerk hängen oder eigene Steuerungsrechner haben. Reine Bürobetriebe lassen diesen Typ einfach weg.

---

## Zu D: Basis-Richtlinien & Dokumentenlenkung

### „Müssen wir 25 verschiedene Richtlinien schreiben, bevor der Auditor kommt?“
- **Antwort:** **Nein.** ISO 27001 schreibt keine bestimmte Anzahl an Dokumenten vor — entscheidend ist, dass alle relevanten Themen geregelt sind.
- **Pragmatische Lösung:** Starten Sie mit den 4 Kern-Richtlinien (`POL-001` bis `POL-004`) und ergänzen Sie nur das, was Sie wirklich brauchen (z. B. eine kompakte *Backup- & Patch-Richtlinie* und eine *Lieferanten-Richtlinie*). Mehrere verwandte Themen dürfen problemlos in **einem** Dokument stehen, solange sie eigene `##`-Unterkapitel mit `<a id="..."></a>`-Ankern haben.

### „Wir haben schon gute Anleitungen im internen Wiki / Confluence / SharePoint. Muss ich die alle abtippen?“
- **Antwort:** **Nein — nutzen Sie den Document-Wrapper (`external_link` oder `uploaded_file`).** 

- **Pragmatische Lösung:** Legen Sie das bestehende Runbook in `ins-isms` als Dokument mit `source_type = external_link` an und verweisen Sie auf die interne Wiki-URL (inkl. `#anker` für das Unterkapitel). So bleibt Ihr Wiki die „Single Source of Truth“ für die Technik, und `ins-isms` übernimmt sauber die ISO-7.5-Lenkung (Verantwortlicher, Review-Intervall, Freigabe).

### „Was muss ich tun, wenn sich an einer freigegebenen Richtlinie nur ein Tippfehler oder ein Ansprechpartner ändert?“
- **Wichtig zu wissen:** Freigegebene (`approved`) Versionen sind in `ins-isms` aus Revisionsgründen unveränderlich gesperrt.
- **Vorgehen:** Klicken Sie auf **„Neue Entwurfsversion ableiten“** (z. B. `1.0` → `1.1`), korrigieren Sie den Punkt, tragen Sie in der Änderungsnotiz kurz ein „Ansprechpartner aktualisiert“ und geben Sie die Version frei (`approve`). Die alte `1.0` wird automatisch archiviert.

---

## Zu E: Statement of Applicability (SoA) & Nachweise

### „Wann darf ich ein ISO-Control auf ‚Nicht anwendbar‘ setzen — und wann gibt es Ärger mit dem Auditor?“
- **Erlaubt (und erwartet):** Wenn der zugehörige Prozess im Unternehmen schlicht nicht existiert.
  - *Klassisches Beispiel:* Sie entwickeln keine eigene Software und lassen auch keine individuell programmieren → Controls `A.8.25` bis `A.8.31` (*Sichere Softwareentwicklung*) auf **Nicht anwendbar** setzen mit Begründung: *„Im Geltungsbereich findet keine eigene Softwareentwicklung statt; es wird ausschließlich Standardsoftware eingesetzt.“*
  - Wenn Sie aber vielleicht kleine Tools, Shellscripte und Automatisierungen entwickelt haben, ist das auch eine Form von Softwareentwicklung uns sie lassen Sie das Control auf **Anwendbar** stehen.
  - *Weiteres Beispiel:* Sie arbeiten 100 % im Homeoffice / Coworking ohne eigene Serverräume → Physische Zutritts-Controls (`A.7.1`–`A.7.4`) auf **Nicht anwendbar** setzen mit Verweis auf den Cloud-/Hosting-Anbieter.
- **Verboten (sofortiges Audit-Finding!):** Ein Control ausschließen, weil es „zu teuer ist“, „bei 15 Mitarbeitern nicht lohnt“ oder „wir noch nicht dazu gekommen sind“.
  - *Richtiges Vorgehen stattdessen:* Control auf **Anwendbar** lassen, Status auf **Nicht begonnen** oder **In Umsetzung** setzen und eine Maßnahme mit Zieldatum anlegen! Unfertige Controls sind im Stage-1-Audit völlig normal, falsch ausgeschlossene Controls nicht. 

### „Wie viel Begründung muss bei den anderen 85 anwendbaren Controls stehen?“
- **Pragmatische Lösung:** Halten Sie es kurz und prägnant (1–2 Sätze genügen völlig), z. B.:
  - *„Anwendbar aufgrund der Verarbeitung vertraulicher Kundendaten und gesetzlicher Vorgaben (DSGVO/BSIG). Umsetzung durch Richtlinie POL-002 und technische Konfiguration in Microsoft 365.“*

### „Was akzeptiert der Auditor als guten Nachweis (`control_evidences`)?“
- **Faustregel für 100 % Audit-Sicherheit:** Ein guter Nachweis belegt **Regelung + gelebte Umsetzung**:
  1. **Richtlinien-Deep-Link (`policy_link`):** Verweist exakt auf den Abschnitt in Ihrer freigegebenen Policy (z. B. `POL-002` → `#mfa-pflicht`).
  2. **Praktischer Beleg (`file` oder `note`):** Ein aktueller Export/Screenshot aus dem System (z. B. Screenshot der Conditional-Access-/MFA-Policy, Protokoll des letzten Backup-Restore-Tests, Export der aktuellen Firewall-Regeln).
- **Tipp:** Laden Sie keine 500-seitigen Logfiles hoch — ein datierter Screenshot oder ein 1-seitiges Prüfprotokoll als PDF reicht völlig.

---

## Zu F: Risikomanagement (5×5-Matrix)

### „Wie viele Risikoszenarien braucht ein KMU wirklich?“
- **Daumenregel:** **12 bis 25 konkrete, realistische Szenarien** sind für ein KMU ideal.
- **Stolperstein:** Schreiben Sie keine abstrakten Ein-Wort-Risiken wie „Hackerangriff“ oder „Datenverlust“.
- **Gute Formulierung (Ursache → Ereignis → Folge):**
  - *„Verschlüsselung der Dateiserver und Backups durch Ransomware nach Phishing-E-Mail führt zu mehrtägigem Betriebsstillstand.“*
  - *„Übernahme eines ungeschützten Admin- oder Cloud-Kontos (Credential Stuffing / Phishing) führt zum Abfluss vertraulicher Kundendaten (C3).“*
  - *„Verlust oder Diebstahl eines unverschlüsselten Firmen-Laptops auf Dienstreise führt zur Offenlegung von Personal- und Vertragsdaten.“*

### „Wie bewerte ich Wahrscheinlichkeit und Auswirkung (1–5), ohne stundenlang zu diskutieren?“
Nutzen Sie diese kompakte KMU-Skala als Basis für Ihre Einteilung:

| Stufe | Eintrittswahrscheinlichkeit | Auswirkung (Schaden) |
| :--- | :--- | :--- |
| **1 – Sehr gering** | Höchstens alle 10+ Jahre denkbar | Kaum spürbar (< 2 Std. Störung, < 1.000 €) |
| **2 – Gering** | Alle 3–10 Jahre möglich | Lokaler Mehraufwand in einem Team, keine Außenwirkung |
| **3 – Mittel** | Alle 1–3 Jahre realistisch | Ausfall einer Abteilung bis 1 Tag oder spürbarer Schaden (z. B. 5.000–25.000 €) |
| **4 – Hoch** | Mehrmals pro Jahr wahrscheinlich | Schwerer Betriebsausfall (> 1 Tag) oder meldepflichtige DSGVO-/NIS2-Panne (`C3`) |
| **5 – Sehr hoch** | Akut / monatlich zu erwarten | Existenzbedrohender Stillstand, Verlust von Kern-IP (`C4`) oder schwere Haftung |

### „Wann darf ein Risiko auf ‚Akzeptiert‘ gesetzt werden?“
- Nur wenn weitere Schutzmaßnahmen wirtschaftlich völlig unverhältnismäßig wären (z. B. ein zweites, georedundantes Rechenzentrum für eine 15-Mann-Firma).
- Bei hohem oder kritischem Restrisiko (`Score ≥ 10`) verlangt `ins-isms` zurecht eine schriftliche Begründung und den Sign-Off durch `iso` oder `admin` — idealerweise nach Rücksprache mit der Geschäftsführung.

---

## Zu G: Maßnahmenplan & Compliance-Kalender

### „Welche wiederkehrenden Routineaufgaben sollte ich sofort anlegen?“
Damit im Audit sichtbar ist, dass Ihr ISMS nicht nur ein einmaliges Projekt war, legen Sie direkt diese **5 Standard-Serienaufgaben** unter `Actions` an:

| Aufgabe | Empfohlenes Intervall | ISO-Control |
| :--- | :--- | :--- |
| Backup-Restore-Test durchführen & protokollieren | Quartalsweise (`quarterly`) | `A.8.13` |
| Admin-Konten & kritische Zugriffsrechte prüfen | Halbjährlich (`semi_annually`) | `A.5.18` |
| Schwachstellen- & Patch-Status kritischer Systeme prüfen | Quartalsweise (`quarterly`) | `A.8.8` |
| Notfall- / Wiederanlaufübung (Tabletop-Übung) durchführen | Jährlich (`annually`) | `A.5.30` |
| Kritische Dienstleister / Lieferanten bewerten | Jährlich (`annually`) | `A.5.22` |

### „Was bedeutet ‚CAPA‘ und warum kann ich manche Maßnahmen nicht selbst schließen?“
- **CAPA** steht für *Corrective and Preventive Action* (Korrektur- und Vorbeugungsmaßnahme).
- Wenn eine Maßnahme aus einem **Audit-Finding** oder einem **Sicherheitsvorfall** entstanden ist, verlangt ISO 27001 Kap. 10.2 eine unabhängige **Wirksamkeitsprüfung (`verification_note`)** durch den ISB (`iso`/`admin`): Erst prüfen, ob die Maßnahme das Problem wirklich dauerhaft gelöst hat (und es im System belegen/dokumentieren) und dann auf **Erledigt** setzen.

---

## Zu H: Vorfälle, Internes Audit & Management-Bewertung

### „Was zählt als Sicherheitsvorfall (`Incidents`) — muss ich da jeden geblockten Spam eintragen?“
- **Nein.** Geblockter Spam oder ein automatisch abgewehrter Portscan sind normale Betriebsereignisse, keine Vorfälle.
- **Eintragen sollten Sie:** Alles, wo eine Schutzmaßnahme umgangen wurde oder ein Beinahe-Schaden entstanden ist — z. B. erfolgreicher Phishing-Klick eines Mitarbeiters, verlorenes Firmenhandy, versehentlich an falschen Empfänger gesendete E-Mail mit Kundendaten, ungeplanter Serverausfall über mehrere Stunden oder Malware-Fund auf einem Client.
- **Tipp für das Audit:** 2–5 sauber dokumentierte kleinere Vorfälle inkl. *Lessons Learned* sind im Audit viel besser als „0 Vorfälle im ganzen Jahr“ (letzteres glaubt kein Auditor und das deutet auf fehlende Meldekultur hin).

### „Ich bin der einzige ISB in der Firma — darf ich das interne Audit (`Audits`) selbst durchführen?“
- **Wichtige ISO-27001-Regel (Kap. 9.2):** Niemand darf seine eigene Arbeit auditieren.
- **Pragmatische KMU-Lösungen (ohne teures Beratungshaus):**
  1. **Cross-Audit mit einem Kollegen:** Ein technisch versierter Kollege aus einer anderen Abteilung (z. B. Qualitätsmanagement oder Entwicklung) auditiert die IT-Controls anhand der Audit-Leitfragen im SoA, und Sie auditieren im Gegenzug die Personal-/Verwaltungsprozesse.
  2. **Halbtägiger externer Freelancer:** Wenn niemand intern Zeit hat, reicht oft ein halber bis ganzer Tag eines freien Auditors nur für das interne Audit (oftmals deutlich günstiger als eine komplette ISMS-Einführungsberatung).
- **Wichtig:** Wenn beim internen Audit 2–3 kleinere Abweichungen (Minor NC oder Beobachtungen) gefunden und sauber per Maßnahme behoben werden, ist das für das Zertifizierungsaudit ein Qualitätsmerkmal/Bonus, kein Makel!

### „Wann muss ich die Management-Bewertung (`Management-reviews`) machen?“
- **Mindestens einmal jährlich** — und zwingend vor dem Zertifizierungsaudit (Stage 1 / Stage 2).
- **Ablauf in `ins-isms`:**
  1. Neue Management-Bewertung anlegen (das System zieht automatisch alle aktuellen Kennzahlen aus SoA, Risiken, Vorfällen, Dokumenten, Maßnahmen und Audits).
  2. In einem 45- bis 60-minütigen Termin mit der Geschäftsführung die Zahlen durchgehen.
  3. Konkrete Beschlüsse der Geschäftsführung festhalten (z. B. Budget für MFA/Backup-Erweiterung freigegeben, Scope bleibt unverändert, Sicherheitsziele für das nächste Jahr bestätigt).
  4. Auf **Freigeben (`Approve`)** klicken — damit wird der Kennzahlen-Stand revisionssicher eingefroren und kann direkt als PDF unterschrieben oder ins Auditor-Paket übernommen werden.
