# Squadtime-Bedrohungsmodell

## Schutzgüter

- Private Profile und Spiele-Inventare
- Verfügbarkeit, Einladungen, Zusagen und Gruppenereignisse
- Getrennte Familien- und Gruppenbereiche einschließlich Guardian-Rechten
- Geräte- und Gruppen-Schlüssel sowie die Integrität von Mitgliedschaft und Historie
- Zugangsdaten und Betriebsdaten des DEV-Relays

## Annahmen und Grenzen

Die Clients verschlüsseln Inhalte Ende zu Ende; der Server hält keinen Master-Schlüssel. IDs, Routen und notwendige Betriebsmetadaten bleiben sichtbar. Verfügbarkeitsberechnung und Terminvorschläge erfolgen lokal. Ein kompromittiertes oder entsperrtes Endgerät kann entschlüsselte Daten offenlegen. E2EE verhindert weder Screenshots noch, dass ein berechtigtes Mitglied bereits gelesene Inhalte behält.

Der erste Relay ist nur für synthetische Testclients vorgesehen. Zufällige, bereichsgebundene Bearer-Credentials werden gehasht gespeichert. Es gibt keine öffentliche Kontoerstellung und kein fertiges Identitäts-Onboarding.

## Bedrohungen und Gegenmaßnahmen

| Bedrohung | Auswirkung | Erforderliche Behandlung / Status |
| --- | --- | --- |
| Datenbank-, Speicher- oder Backup-Zugriff | Offenlegung von Profilen, Inventaren oder Gruppeninhalten | Anwendungsinhalte nur als Chiffretext speichern; Schlüssel nicht serverseitig hinterlegen. Metadaten bleiben ein Restrisiko. |
| Böswilliger oder kompromittierter Server ersetzt öffentliche Geräteschlüssel | Client verschlüsselt künftig an einen Angreifer; Server kann sich zwischen Geräten schalten | Schlüsselbindung und Authentizität müssen unabhängig prüfbar sein. Verifikations- und Änderungsfluss ist offen; ein Verzeichnis allein schützt nicht gegen Serverersetzung. |
| Entzogenes Gerät oder Mitglied | Zugriff auf künftig gelieferte Gruppendaten | Entzug und Schlüsselrotation müssen zukünftige Inhalte schützen. Bereits erhaltene Inhalte lassen sich nicht unlernen und nicht zuverlässig zurückholen. Rotation und Mitgliedschaftsprotokoll sind offen. |
| Replay, Reihenfolgeänderung oder Rollback | Alte Verfügbarkeit, Mitgliedschaften oder Ereignisse werden erneut gültig bzw. angezeigt | Nachrichten müssen authentisiert und an Gruppe, Epoche/Version und Sequenz gebunden sein. Anti-Replay und verlässliche Zustandsfortschreibung sind noch zu spezifizieren. |
| Missbrauch von Guardian-Rechten oder Wiederherstellung | Unberechtigtes Lesen oder dauerhafter Ausschluss des Kindes | Guardian-Zugriff muss explizit erteilt, begrenzt und widerrufbar sein. Wiederherstellung darf keinen versteckten Server-Master-Schlüssel voraussetzen. Berechtigungsmodell ist offen. |
| Logs, Fehlerberichte oder Traces enthalten Klartext/Secrets | Offenlegung von Inhalten oder Zugangsdaten | Keine Klartextinhalte, Schlüssel, Tokens oder privaten Nutzdaten in Logs. Strukturierte Logs auf minimale Status- und Korrelationsdaten begrenzen; Redaktion vor Ausgabe. |
| Sichtbare IDs, Routen, Größen und Zeitpunkte | Beziehungs-, Aktivitäts- oder Nutzungsprofile trotz E2EE | Metadateninventar minimieren; Zugriff und Aufbewahrung begrenzen. Vollständiges Verbergen von Routing und Zeitpunkten ist nicht zugesagt. |
| Spiele-Proxy/IGDB-Anfragen | IP-Adresse und Anfragezeitpunkt des Servers gehen an IGDB; angefragte Spiele können Rückschlüsse auf Nutzer zulassen | Clients rufen IGDB nicht direkt auf. Proxy nur mit notwendigen IDs, Cache und knapper Aufbewahrung; keine Nutzer- oder Gruppenkennung an IGDB senden. |
| Push-Zeitpunkt und Plattformanbieter | APNs/FCM können Geräte- und Zustellzeitpunkte sehen; Push-Muster verraten Aktivität | Neutrale Push-Texte ohne private Inhalte. Push möglichst generisch und gebündelt gestalten. Weniger präzise Benachrichtigung senkt Timing-Leaks, verzögert aber Updates; genaue Abwägung offen. |
| Gestohlene Relay-Credentials | Unberechtigter Zugriff im DEV-System | Zufällige, zweck-/bereichsgebundene Tokens; nur Hashes speichern; rotieren und widerrufen können; nie in Git oder Logs ablegen. Nur synthetische Testdaten. |

## Nicht gelöste Sicherheitsfragen

Vor realen Nutzerkonten müssen insbesondere Schlüssel-Lebenszyklus, freigegebene Geräte, Mitgliederautorisierung und Widerruf, Guardian-Zugriff, Wiederherstellung, Schlüsselersetzungs-Erkennung sowie Replay-/Rollback-Schutz entworfen und geprüft werden. MLS bleibt Evaluierung und ist keine festgelegte Produktionswahl.
