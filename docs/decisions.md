# Architekturentscheidungen

Statusangaben beziehen sich auf den aktuellen Projektstand. „Angenommen“ bezeichnet eine getroffene Richtungsentscheidung; es ist keine Behauptung, dass der Betrieb bereits produktionsreif ist.

## Angenommen

### A-001: Cloudflare-Backend mit EU-Datenhaltung

**Entscheidung:** API mit Cloudflare Workers und TypeScript, D1 in der EU. R2 in der EU kommt bei Bedarf später hinzu.

**Grund:** Serverlose gemeinsame API und EU-Datenhaltung für den geplanten Dienst.

**Grenze:** Cloudflare ist ein US-Unternehmen. EU-Speicherort allein beantwortet keine Fragen zu Auftragsverarbeitung oder möglichem grenzüberschreitendem Zugriff.

### A-002: Ende-zu-Ende-Verschlüsselung und lokale Planung

**Entscheidung:** Private Profile und Spiele-Inventare sowie Verfügbarkeit und Ereignisse je Gruppe werden clientseitig verschlüsselt. Verfügbarkeitsüberschneidungen und Terminvorschläge werden lokal berechnet.

**Folge:** Kein serverseitiger Master-Schlüssel. Notwendige IDs, Routen und Betriebsmetadaten bleiben sichtbar. Der Familienbereich ist getrennt vom Gruppenbereich.

### A-003: Login-Schlüssel und Geräteschlüssel trennen

**Entscheidung:** Passkey/Anmeldung dient nicht als Ersatz für Geräteschlüsselmaterial. Geräteverschlüsselung, Guardian-Freigabe und Wiederherstellung benötigen ein eigenes, ausdrücklich autorisiertes Modell.

**Status:** Grundsatz angenommen; konkrete Protokolle und Abläufe offen.

### A-004: Entwicklungs-Relay vor Identitäts-Onboarding

**Entscheidung:** Zuerst ein DEV-Relay mit synthetischen Testclients und zufälligen, begrenzt gültigen Bearer-Credentials, deren Hashes gespeichert werden.

**Grenze:** Keine öffentliche Kontoerstellung und kein fertiges Endnutzer-Identitäts-Onboarding.

### A-005: Kein Geheimnis in Git

**Entscheidung:** Keine Zugangsdaten, privaten Schlüssel, Tokens oder produktiven Kontokennungen in Git. Öffentliche Repository-Inhalte dürfen keine privaten Konto-E-Mail-Adressen oder Cloudflare-Konto-IDs enthalten.

## Offen

- **Schlüssel-Lebenszyklus:** Erzeugung, Gerätebindung, Rotation, Backup, Wiederherstellung und Löschung.
- **Gerätefreigabe und Mitgliedschaft:** Wie ein neues Gerät authentisch aufgenommen wird, wer Mitglieder autorisiert und wie Entzug gegenüber verbleibenden Geräten durchgesetzt wird.
- **Vergangenheit nach Widerruf:** Entzogene Clients dürfen zukünftige Inhalte nach Rotation nicht lesen. Bereits entschlüsselte oder gespeicherte Inhalte kann ein Client nicht vergessen; vergangener Zugriff lässt sich nicht rückgängig machen.
- **Guardian-Modell:** Explizite, begrenzte und widerrufbare Zugriffs- und Wiederherstellungsrechte unter Wahrung der Trennung zwischen Familien- und Gruppenbereich.
- **Böswilliger Server und Schlüsselersetzung:** Wie Clients erkennen und verifizieren, dass Schlüssel nicht durch den Server ausgetauscht wurden.
- **Replay und Rollback:** Authentisierung von Reihenfolge, Version/Epoche und Mitgliedschaftszustand sowie Erkennung veralteter Zustände.
- **Metadaten:** Exaktes Inventar sichtbarer IDs, Routen, Zeitpunkte, Größen und Aufbewahrung.
- **Protokollwahl:** MLS wird evaluiert; es gibt noch keine Festlegung für den Produktivbetrieb.
- **Push-Granularität:** Abwägung zwischen zeitnahen Updates und dem Schutz vor Rückschlüssen aus Zustellzeitpunkten.

## Sicherheitsleitlinien bis zur Klärung

Keine Klartexte, Schlüssel oder Zugangstokens protokollieren. Relay-Daten synthetisch halten. Keine Behauptung, dass E2EE Routing-Metadaten, Push-Zeitpunkte, bereits gelesene Daten oder kompromittierte Endgeräte verbirgt.
