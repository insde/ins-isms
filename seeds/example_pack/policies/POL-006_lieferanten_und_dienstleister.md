# Richtlinie zur Informationssicherheit bei Lieferanten und Dienstleistern

<a id="ziel-geltungsbereich"></a>
## 1. Zielsetzung und Geltungsbereich
Ziel dieser Richtlinie ist es, Risiken für unsere Informationen und IT-Systeme zu minimieren, die durch die Zusammenarbeit mit externen Dienstleistern, Cloud-Anbietern, Telekommunikations-Carriern und Lieferanten entstehen. Sie gilt für alle externen Partner, die Zugriff auf unsere Systeme erhalten, vertrauliche Daten (`C3`/`C4`) verarbeiten oder geschäftskritische IT- und Netzdienste bereitstellen.

<a id="auswahl-vertraege"></a>
## 2. Auswahl und vertragliche Absicherung
- Vor der Beauftragung kritischer Dienstleister werden deren Sicherheitsniveau und Zuverlässigkeit geprüft.
- Mit allen Dienstleistern, die Zugriff auf vertrauliche Daten erhalten, sind verbindliche Geheimhaltungsvereinbarungen (NDA) sowie bei Verarbeitung personenbezogener Daten ein Auftragsverarbeitungsvertrag (AVV nach Art. 28 DSGVO) abzuschließen.
- Die vertraglichen Vereinbarungen regeln klare Zuständigkeiten für Informationssicherheit, Meldepflichten bei Sicherheitsvorfällen sowie Vorgaben zur Datenrückgabe und -löschung bei Vertragsende.

<a id="carrier-upstream"></a>
## 3. Netz- und Upstream-Provider (Carrier & Internetzugänge)
- Für geschäftskritische Internetzugänge und Rechenzentrums-Uplinks werden verbindliche Service-Level-Agreements (SLAs) zu Verfügbarkeit, Reaktions- und Entstörzeiten vereinbart.
- Kritische Anbindungen (insbesondere Hosting- und Produktiv-Uplinks) sind nach Möglichkeit redundant über unabhängige Upstream-Provider und physisch getrennte Leitungswege auszulegen, um Single Points of Failure zu vermeiden.
- Da öffentliche Transportnetze grundsätzlich als nicht vertrauenswürdig gelten, ist für jegliche Übertragung vertraulicher Daten eine durchgehende Transportverschlüsselung (z. B. TLS, VPN, SSH) zwingend einzusetzen.

<a id="ueberwachung-audits"></a>
## 4. Regelmäßige Bewertung und Lieferantenaudits
- Kritische Lieferanten und IT-Dienstleister werden im ISMS-Inventar geführt und mindestens einmal jährlich hinsichtlich ihrer Sicherheitsleistung und Vertragserfüllung bewertet.
- Die Überprüfung erfolgt risikoorientiert und verhältnismäßig:
  - **Stufe 1 (Standard / Cloud- & Telekommunikationsanbieter):** Prüfung aktueller Zertifizierungen (z. B. ISO 27001, SOC 2 Typ II, BSI C5), regulatorischer Vorgaben sowie der vertraglichen SLAs.
  - **Stufe 2 (Erhöhter Schutzbedarf / individuelle Dienstleister):** Einholung einer strukturierten Selbstauskunft (Sicherheitsfragebogen) und Prüfung vereinbarter Service-Level-Agreements.
  - **Stufe 3 (Hohes Risiko / Vor-Ort-Audit):** Bei besonders kritischen Abhängigkeiten oder konkreten Sicherheitsvorfällen behält sich das Unternehmen das Recht auf gezielte Audits oder Einsichtnahmen vor.

<a id="aenderungen-beendigung"></a>
## 5. Änderungen und Beendigung von Dienstleistungen
- Wesentliche Änderungen an der Dienstleistungserbringung (z. B. Einsatz neuer Unterauftragnehmer oder Verlagerung von Rechenzentrumsstandorten) sind durch den Dienstleister vorab anzuzeigen und hinsichtlich neuer Risiken zu bewerten.
- Bei Beendigung einer Geschäftsbeziehung werden sämtliche Zugänge, API-Schlüssel und Berechtigungen des Dienstleisters unverzüglich entzogen.
