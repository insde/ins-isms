# Richtlinie zur Passwort- und Zugriffssicherheit

<a id="zugriffsrechte"></a>
## 1. Grundsatz und Zugriffsrechte (Minimalprinzip)
Zugriffsrechte auf IT-Systeme, Anwendungen und Daten werden ausschließlich nach dem **Need-to-know-Prinzip** (nur so viel Zugriff wie für die jeweilige Aufgabe erforderlich) vergeben. Sammelkonten (Shared Accounts) sind grundsätzlich unzulässig.

- Bei Ausscheiden oder Aufgabenwechsel von Mitarbeitenden werden alle Zugriffsrechte unverzüglich entzogen bzw. angepasst.
- Berechtigungen auf vertrauliche Systeme werden mindestens jährlich durch die jeweiligen Verantwortlichen überprüft.

<a id="mfa-pflicht"></a>
## 2. Multi-Faktor-Authentifizierung (MFA)
Der Einsatz von Multi-Faktor-Authentifizierung (MFA) ist verpflichtend für:
- Alle Fernzugriffe auf das Unternehmensnetzwerk (VPN)
- Alle Cloud-Dienste und E-Mail-Konten
- Sämtliche administrativen und privilegierten Benutzerkonten

<a id="passwort-regeln"></a>
## 3. Passwortregeln
Sofern keine passwortlose Authentifizierung (z. B. Passkeys / FIDO2) genutzt wird, gelten folgende Mindestanforderungen:
- **Mindestlänge:** Mindestens 12 Zeichen (für administrative Konten mindestens 16 Zeichen).
- **Einzigartigkeit:** Dienstliche Passwörter dürfen niemals für private Dienste wiederverwendet werden.
- **Passwort-Manager:** Zur sicheren Verwaltung komplexer Passwörter ist der vom Unternehmen bereitgestellte Passwort-Manager zu nutzen.
- **Weitergabeverbot:** Passwörter sind streng persönlich und dürfen weder mündlich, schriftlich noch per E-Mail weitervergegeben werden.
- Bei Verdacht auf Kompromittierung ist das Passwort umgehend zu ändern und der IT-Support bzw. ISB zu informieren.

<a id="admin-konten"></a>
## 4. Privilegierte und administrative Konten
Administrative Tätigkeiten dürfen nicht mit dem regulären Büro-Benutzerkonto durchgeführt werden. Für Systemadministration sind dedizierte Admin-Konten mit MFA und protokolliertem Zugriff zu verwenden.
