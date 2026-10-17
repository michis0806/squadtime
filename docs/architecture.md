# Squadtime-Architektur

## Zweck und Status

Dieses Dokument hält die angenommene Zielarchitektur und den aktuellen Entwicklungsstand fest. Es ergänzt das Produktkonzept; es ändert dessen Produktumfang nicht. Sicherheitsdetails, die noch keine belastbare Entscheidung haben, stehen unter „Offen“.

## Systembild

- **Clients:** native iOS- und Android-Apps. Sie berechnen Überschneidungen und Terminvorschläge lokal aus entschlüsselten Daten.
- **API:** Cloudflare Workers mit TypeScript. Der Dienst vermittelt verschlüsselte Datensätze und Gruppenoperationen.
- **Datenbank:** Cloudflare D1, EU-Standort. D1 enthält erforderliche Betriebsdaten und verschlüsselte Anwendungsdaten.
- **Objektspeicher:** Cloudflare R2 in der EU ist für spätere Nutzung vorgesehen, nicht Voraussetzung des ersten Relays.
- **Drittanbieter:** Der Spiele-Proxy fragt IGDB ab und liefert Spielmetadaten/Cover. Push erfolgt über APNs und FCM.

Cloudflare ist ein US-Unternehmen. Die EU-Region reduziert die geografische Speicherung, beseitigt aber nicht die Bedeutung von Auftragsverarbeitung, Zugriffskontrollen und einer Prüfung der grenzüberschreitenden Datenverarbeitung.

## Verschlüsselungsgrenzen

Ende-zu-Ende-Verschlüsselung ist für private Profildaten und Spiele-Inventar sowie für Verfügbarkeit und Ereignisse je Gruppe vorgesehen. Server und Speicher erhalten dafür Chiffretext; sie besitzen keinen allgemeinen Entschlüsselungs- oder Master-Schlüssel.

Der Familienbereich ist logisch und kryptografisch vom Gruppenbereich getrennt. Elternzugriff und Wiederherstellung müssen ausdrücklich autorisiert werden; sie dürfen nicht aus einem gemeinsamen Kontoschlüssel oder bloßer Serveradministration folgen.

Anmeldung/Passkeys und Verschlüsselungsschlüssel für Geräte sind getrennte Dinge. Eine erfolgreiche Anmeldung allein darf kein bestehendes Geräteschlüsselmaterial ersetzen oder entschlüsseln. Der DEV-Relay ist keine fertige Identitäts- oder Endnutzer-Onboarding-Lösung.

Serverseitig sichtbar bleiben mindestens notwendige Routing- und Betriebsmetadaten, darunter IDs, Mitgliedschafts-/Zugriffsbeziehungen, Zeitpunkte und angefragte Routen. Das genaue Metadateninventar ist noch festzulegen und zu minimieren. Der Server soll keine Inhaltsdaten entschlüsseln.

## Entwicklungsstand: DEV-Relay

Der erste Backend-Schritt ist ein Entwicklungs-Relay für synthetische Testclients. Es verwendet zufällige, zweck- und bereichsgebundene Bearer-Zugangsdaten; gespeichert werden davon nur Hashes. Es gibt keine öffentliche Kontoerstellung und noch kein fertiges Endnutzer-Identitäts-Onboarding. Zugangsdaten gehören weder in Git noch in Dokumentation, Logs oder Beispielkonfigurationen.

## Datenfluss

1. Clients verschlüsseln Inhalte mit lokal gehaltenem Schlüsselmaterial.
2. Sie senden Chiffretext und die für Routing und Berechtigungsprüfung erforderlichen Metadaten an den Worker.
3. Worker prüft den Zugriff, speichert oder liefert Chiffretext und gibt keine Klartextdaten in Logs aus.
4. Geräte entschlüsseln und berechnen Verfügbarkeitsüberschneidungen sowie Terminvorschläge lokal.
5. Push-Nachrichten bleiben neutral und enthalten keine privaten Inhalte; ihre Zeitpunkte können dennoch Aktivität offenbaren.

## Noch festzulegen

Vor Endnutzerbetrieb sind Schlüssel-Lebenszyklus und Gerätefreigabe, explizite Mitgliederautorisierung, Guardian-Zugriff und Wiederherstellung, Schutz gegen Schlüsselersetzung durch einen böswilligen Server, Replay- und Rollback-Schutz sowie Löschung und Rotation auszuarbeiten. MLS wird evaluiert, ist aber keine festgelegte Produktionslösung.
