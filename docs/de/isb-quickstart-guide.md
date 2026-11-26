# ISB-Quickstart: Erste Schritte & Reihenfolge der Dateneingabe

Ein Informationssicherheits-Managementsystem (ISMS) nach **ISO 27001** baut logisch aufeinander auf: Ohne definierten Geltungsbereich (Scope) und Inventar lassen sich Risiken nicht sauber bewerten, und ohne bewertete Risiken fehlt dem Statement of Applicability (SoA) die Begründung.

Im Rahmen der Anforderungen der Norm gibt es viele Varianten, wie man ein ISMS strukturieren kann. 

Das ins-isms ist allerdings „opinionated“, es hat feste Vorgaben, Strukturen und „Best Practices“ statt maximaler Flexibilität und kann so helfen, ein ISMS sinnvoll zu strukturieren, wenn man noch nicht so viel Erfahrung damit hat. Die im ins-isms vorgegebene Struktur und Arbeitsweise mag aber nicht für jeden passen.

Halten Sie bei der Ersteinrichtung und dem Aufbau des **ins-isms** diese **Reihenfolge** ein.

---

## A: Organisationsprofil, Geltungsbereich & Rollen einrichten
1. **ISO Katalog und Richtlinen einrichten/einlesen:**
2. **Organisationsprofil pflegen:**
   - Hinterlegen Sie den offiziellen **Organisationsnamen** und formulieren Sie den **ISMS-Geltungsbereich (Scope Statement)** gemäß ISO 27001 Kap. 4.3 (z. B. *„Entwicklung, Betrieb und Support der Cloud-Plattform am Standort Musterstadt inklusive Verwaltung und IT-Infrastruktur“*). Dieser Text erscheint automatisch auf allen PDF-Deckblättern und im Audit-Kompendium.
   - Wählen Sie die Ziel-Regelwerke (`ISO27001_2022`, optional `NIS2_DE`).
3. **Organisationseinheiten anlegen:**
   - Erfassen Sie Ihre Abteilungen/Bereiche (z. B. *Geschäftsführung*, *IT-Betrieb*, *Softwareentwicklung*, *Personal & Finanzen*, *Vertrieb*)  
4. **Benutzer & Rollen anlegen:**
   - Trennen Sie administrative Rechte (`admin`) und fachliche ISB-Verantwortung (`iso`).
   - Legen Sie Abteilungs- und Systemverantwortliche mit der Rolle `owner` an und ordnen Sie ihnen ihre `organization_unit` zu (dadurch sehen und pflegen sie nur ihre eigenen Bereiche).
   - Legen Sie Mitarbeiter (`employee`) an, die später Richtlinien per Lesebestätigung abzeichnen sollen.
---
## B: Schutzstufen prüfen & Informationswerte erfassen (ISO A.5.12 / A.5.13)
Bevor Sie IT-Systeme bewerten, definieren Sie, **welche Informationen** im Unternehmen verarbeitet werden – denn der Schutzbedarf z.B. eines Servers ergibt sich aus den Daten, die darauf liegen.
1. **Handling-Matrix prüfen:**
   - Prüfen Sie die vorausgefüllten vier Schutzstufen (`C1` Öffentlich, `C2` Intern, `C3` Vertraulich, `C4` Streng vertraulich) und passen Sie die Umgangsregeln (Speicherung, Übertragung, Kennzeichnung, Zugriff, Löschung) an Ihre betriebliche Praxis an.
2. **Informationswerte anlegen:**
   - Erfassen Sie Ihre zentralen Datenkategorien (z. B. *Kundendatenbank*, *Personalakten*, *Finanz- und Lohnbuchhaltung*, *Quellcode & Zugangsdaten*, *Verträge & Angebote*).
   - Ordnen Sie jedem Informationswert eine **Schutzstufe (`C1`–`C4`)**, den Schutzbedarf nach **CIA (`Normal`, `Hoch`, `Sehr hoch`)**, eine **Aufbewahrungsfrist** (z. B. *10 Jahre nach HGB/AO*) sowie einen **Verantwortlichen (`owner`)** zu.
   - *Tipp:* Für größere Bestände von Informationswerten können Sie den **CSV-Import** unter `Exports` nutzen.
---
## C: IT-Systeme, Standorte & kritische Lieferanten inventarisieren (ISO A.5.9 / A.5.19)
1. **System-Assets anlegen:**
   - Erfassen Sie logische System- oder Gerätegruppen (Server/Infrastruktur, Anwendungen/Software, Cloud-Dienste, Netzwerk, standardisierte Endgeräte-Gruppen wie *Standard-Notebooks Windows 11*), physische Standorte/Räume (`facility`), Maschinen/OT-Anlagen (`ot_equipment`), kritische IT-Dienstleister/Lieferanten (`vendor`) sowie sonstige Assets (`other`).
   - Vergeben Sie sprechende Codes (`SYS-001`, `SYS-002`, …) und weisen Sie jedem System-Asset jeweils einen Systemverantwortlichen zu.
2. **Informationswerte mit IT-Systemen verknüpfen:**
   - Verknüpfen Sie im Detail-Drawer jedes Informationswerts die verarbeitenden IT-Systeme (z. B. *Personalakten* → *ERP/HR-System* + *Backup-Speicher*).
   - **Automatischer Effekt (Maximumprinzip):** `ins-isms` berechnet nun für jedes IT-System dynamisch die höchste geerbte Schutzstufe (`C1`–`C4`) und den höchsten CIA-Schutzbedarf.
---
## D: Basis-Richtlinien prüfen & freigeben (ISO Kap. 7.5 / A.5.1)
1. **Starter-Richtlinien anpassen:**
   - Öffnen Sie die vier vorinstallierten Entwürfe (`POL-001` Informationssicherheitsleitlinie, `POL-002` Passwort- und Zugriffsschutz, `POL-003` Mobiles Arbeiten & Endgeräte, `POL-004` Vorfallmeldung & NIS2).
   - Passen Sie Platzhalter und unternehmensspezifische Regelungen (z. B. Passwortlängen, Meldewege) im Markdown-Editor an. **Behalten Sie die `<a id="..."></a>`-Anker über den Überschriften bei**, damit Deep-Links aus dem SoA exakt funktionieren.
   - Ergänzen Sie eigene bestehende Richtlinien oder externe Wiki-/Confluence-Runbooks (`external_link` / `uploaded_file`).
2. **Richtlinien formal freigeben:**
   - Geben Sie die geprüften Richtlinien als `iso` oder `admin` frei. Erst freigegebene (`approved`) Versionen sind für Prüfer (`auditor`) und Mitarbeiter (`employee`) sichtbar.
3. **Lesebestätigungen anstoßen:**
   - Aktivieren Sie bei mitarbeiterrelevanten Richtlinien (`POL-001` bis `POL-004`) die Pflicht zur Lesebestätigung (`requires_acknowledgment`). Mitarbeiter können diese nun direkt in ihrem Portal abzeichnen.
---
## E: Statement of Applicability (SoA) bewerten & Nachweise verknüpfen (ISO Kap. 6.1.3 d)
1. **Controls bewerten:**
   - Gehen Sie die 93 Controls des **ISO 27001:2022**-Katalogs (und bei NIS2-Betroffenheit zusätzlich die 14 **NIS2/BSIG**-Anforderungen) durch. Nutzen Sie die Tastatur-Triage (`j`/`k` zum Navigieren, `s` für Status, `a` für Anwendbarkeit, `e` für Nachweis).
   - **Wichtig für das Audit:** Wenn ein Control nicht zutrifft (z. B. A.8.25–A.8.31 ohne eigene Softwareentwicklung), setzen Sie es auf *Nicht anwendbar* und hinterlegen Sie eine **nachvollziehbare Begründung** (Pflichtfeld).
   - Nutzen Sie im Detail-Drawer die **Cross-Framework-Abdeckung**, um zu sehen, welche NIS2-Anforderungen durch Ihre ISO-Controls bereits mitabgedeckt sind.
2. **Prüfungsnachweise hinterlegen (`control_evidences`):**
   - Verknüpfen Sie zu umgesetzten Controls konkrete Nachweise:
     - **Richtlinien-Deep-Link:** Verweist direkt auf ein Unterkapitel einer freigegebenen Policy (z. B. `POL-002` → `Kap. 2: Passwort- und Authentifizierungsregeln`).
     - **Datei-Nachweis:** z. B. aktuelles Backup-Protokoll, Firewall-Regelwerk oder Schulungsnachweis (wird mit SHA-256-Prüfsumme gesichert).
     - **Externe URL oder Notiz.**
---
## F: Risiken identifizieren, bewerten & behandeln (ISO Kap. 6.1.2 / 6.1.3)
1. **Risikoszenarien erfassen:**
   - Erfassen Sie relevante Bedrohungsszenarien für Ihre `C3`/`C4`-Informationswerte und kritischen `system_assets` (z. B. *Ransomware-Verschlüsselung*, *Phishing / Kontoübernahme*, *Ausfall eines Cloud-Dienstleisters*, *Verlust eines mobilen Endgeräts*).
   - Verknüpfen Sie das betroffene Informations- oder System-Asset: Bei `C3`/`C4`-Assets schlägt das System automatisch eine angemessene Brutto-Auswirkung (`4` bzw. `5`) vor.
2. **Brutto-Risiko, Controls & Netto-Risiko bestimmen:**
   - Bewerten Sie Eintrittswahrscheinlichkeit (`1–5`) und Auswirkung (`1–5`) vor Maßnahmen (**Brutto-Risiko**).
   - Verknüpfen Sie im Detail-Drawer die risikomindernden **SoA-Controls** und bewerten Sie das verbleibende **Netto-Risiko**.
   - Verbleibt ein hohes oder kritisches Restrisiko (`Score ≥ 10`), erfordert die Risikoakzeptanz eine schriftliche Begründung und den formalen Sign-Off durch `iso` oder `admin`.
---
## G: Maßnahmenplan & Compliance-Kalender starten (ISO Kap. 6.2 / 10.2)
1. **Offene Lücken in Maßnahmen überführen:**
   - Erstellen Sie für alle noch nicht umgesetzten SoA-Controls und risikomindernden Maßnahmen konkrete Aufgaben mit Verantwortlichem (`owner`) und Zieldatum.
2. **Wiederkehrende Routineaufgaben anlegen:**
   - Richten Sie für regelmäßige Nachweispflichten Serienaufgaben ein, z. B.:
     - *Quartalsweise:* Backup-Restore-Test (A.8.13)
     - *Halbjährlich:* Review administrativer Berechtigungen (A.5.18)
     - *Jährlich:* Notfall- und Wiederanlaufübung (A.5.30), Lieferantenbewertung (A.5.22), Sensibilisierungsschulung (A.6.3)
   - Sobald eine Serienaufgabe abgeschlossen wird, erzeugt `ins-isms` automatisch die nächste fällige Instanz.

---
## H: PDCA-Nachweise & Audit-Vorbereitung abschließen (ISO Kap. 9.2 / 9.3)
Bevor das Zertifizierungsaudit (Stage 1 / Stage 2) stattfindet, schließen Sie den ersten PDCA-Zyklus ab. Sie sollten dann ca. 3-6 Monate bereits mit dem ISMS im Tagesgeschäft gearbeitet haben und entsprechende Nachweise gesammelt haben.

1. **Internes Audit durchführen:**
   - Planen und dokumentieren Sie mindestens ein vollständiges internes ISMS-Audit.
   - Erfassen Sie festgestellte Abweichungen (Hauptabweichung, Nebenabweichung, Hinweis) und leiten Sie per One-Click-CAPA Korrekturmaßnahmen ab. Schließen Sie Findings erst nach erfolgreicher dokumentierter Wirksamkeitsprüfung.
2. **Management-Bewertung durchführen:**
   - Erstellen Sie eine neue Management-Bewertung: `ins-isms` aggregiert automatisch alle ISO-9.3-Kennzahlen (SoA-Quote, Risikoprofil, Vorfälle, Dokumentenstatus, offene Maßnahmen und Audit-Findings).
   - Ergänzen Sie die Beschlüsse der Geschäftsführung und geben Sie das Protokoll frei (`approve`), wodurch der Kennzahlen-Snapshot revisionssicher eingefroren wird.
3. **Prüfer-Zugang & Auditor-Paket bereitstellen:**
   - Verifizieren Sie unter `Audit-logs` mit einem Klick die Integrität der kryptografischen SHA-256-Hash-Chain.
   - Legen Sie für Ihren Zertifizierungsauditor einen zeitlich befristeten Benutzer mit Rolle `auditor`an oder exportieren Sie das vollständige **Auditor-Evidence-ZIP** (`00_MANIFEST.sha256` + alle PDFs, CSVs und Nachweise) bzw. das **Gesamt-Audit-Kompendium-PDF**.

---
## I: Externes Audit durchführen
   - **Viel Erfolg!** 
   - Bedenken Sie: Nicht jeder Prüfer prüft gleich intensiv oder macht die gleichen Prüfungen/Stichproben. Wenn Sie es aber mit den obigen Tipps geschafft haben ein ISMS zu implementieren und es leben, dann haben Sie eine gute Ausgangsbasis für das Bestehen der Zertifizierung - auch wenn Ihnen das natürlich niemand versprechen oder garantieren kann. Auch das `ins-isms` kann dieses nicht garantieren.

---
## J: Herzlichen Glückwunsch. 
   - Jetzt heisst es: Einfach genauso weitermachen. 
   - Eine Zertifizierung ist keine einmalige Sache. Ab jetzt arbeiten Sie und die gesamte Firma immer weiter mit dem System. 
   - Und: Nach dem Audit ist vor dem Audit. :-)


