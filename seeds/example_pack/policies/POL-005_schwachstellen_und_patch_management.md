# Richtlinie zum Schwachstellen- und Patch-Management

<a id="ziel-geltungsbereich"></a>
## 1. Zielsetzung und Geltungsbereich
Ziel dieser Richtlinie ist es, Sicherheitslücken in Betriebssystemen, Anwendungen und Infrastrukturkomponenten frühzeitig zu erkennen, nach Risiko zu bewerten und zeitnah zu beheben. Sie gilt für alle intern betriebenen IT-Systeme sowie für alle im Rahmen von Dienstleistungs- und Hosting-Verträgen verwalteten Kundenumgebungen.

<a id="ueberwachung-inventar"></a>
## 2. Systeminventar und Schwachstellenüberwachung
- Alle produktiven Systeme, Anwendungen und verwendeten Software-Komponenten werden in einem aktuellen Inventar geführt.
- Die IT-Abteilung überwacht regelmäßig relevante Sicherheitsmeldungen (z. B. Hersteller-Advisories, CERT-Warnungen) und führt automatisierte Schwachstellen-Scans durch.
- Nicht mehr unterstützte Software (End-of-Life / EOL) ohne Sicherheitsupdates darf nicht produktiv betrieben werden, sofern keine dokumentierten Ausgleichsmaßnahmen (z. B. Netzwerkisolierung) genehmigt wurden.

<a id="reaktionszeiten"></a>
## 3. Bewertung und Reaktionszeiten (Patch-SLAs)
Bekannt gewordene Schwachstellen werden anhand ihres Schweregrads (z. B. CVSS-Score) und der tatsächlichen Exponiertheit bewertet. Ab Bekanntwerden eines verfügbaren Sicherheitsupdates gelten folgende maximale Umsetzungsfristen:

- **Kritisch (CVSS 9.0–10.0 oder aktive Ausnutzung / Zero-Day):** Unverzügliche Prüfung und Behebung bzw. Absicherung durch Workarounds (z. B. WAF-Regeln) innerhalb von **24 bis 48 Stunden**.
- **Hoch (CVSS 7.0–8.9):** Einspielen des Sicherheitsupdates innerhalb von **7 bis 14 Tagen**.
- **Mittel (CVSS 4.0–6.9):** Einspielen im Rahmen des regulären Wartungsfensters innerhalb von **30 Tagen**.
- **Niedrig (CVSS 0.1–3.9):** Behebung im Rahmen regulärer Release- oder Wartungszyklen.

<a id="notfall-patches"></a>
## 4. Notfall-Updates und Kompromittierungsprüfung (IoC-Check)
- Kritische Sicherheitsupdates außerhalb regulärer Wartungsfenster werden als dokumentierter Notfall-Change (Emergency Change) durchgeführt.
- Bei kritischen Schwachstellen in öffentlich erreichbaren Diensten prüft die IT-Abteilung vor oder unmittelbar nach dem Einspielen des Updates die Systemprotokolle auf Anzeichen einer bereits erfolgten Ausnutzung (*Indicators of Compromise*).
- Werden Anzeichen einer Kompromittierung festgestellt oder tritt durch das Update ein ungeplanter Schaden ein, wird der Vorgang unverzüglich gemäß `POL-004` als Sicherheitsvorfall eskaliert.

<a id="verantwortlichkeiten"></a>
## 5. Abgrenzung bei verwalteten Kundensystemen
- Sofern Kundenumgebungen betrieben oder gepflegt werden, richtet sich die Zuständigkeit nach den vertraglich vereinbarten Service-Level-Agreements (z. B. Trennung zwischen Betriebssystem-/Laufzeitumgebung und kundenspezifischer Anwendungslogik).
- Kunden werden über kritische Sicherheitsupdates und erforderliche Wartungsfenster transparent informiert.
