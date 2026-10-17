# Squadtime

Gemeinsame Spielzeiten für Freundesgruppen, mit einem von Eltern gesetzten Rahmen.

**Entwicklungsstand:** technisches Fundament und Protokoll-Erprobung. Kein fertiges Produkt und keine Freigabe für echte Kinder-/Nutzerdaten. Die native iOS-/Android-App, Geräte-Kopplung, Guardian-Berechtigungen und Wiederherstellung sind noch nicht implementiert.

## Bestandteile

- `backend/`: Cloudflare-Worker mit einem authentisierten Relay für undurchsichtige verschlüsselte Ereignisse; D1-Migration.
- `api/openapi.yaml`: gemeinsamer API-Vertrag des DEV-Relays.
- `crypto/mls-spike/`: ausführbare MLS-Protokolltests mit frisch erzeugten Testidentitäten.
- `docs/architecture.md`, `docs/threat-model.md`, `docs/decisions.md`: Architektur, Grenzen und offene Entscheidungen.
- `docs/crypto-spike.md`: Bibliotheksvergleich, Nachweise und bekannte Integrationsgrenzen.
- `squadtime-konzept.md`: ursprüngliches Produktkonzept; bei technischen Abweichungen gelten die neueren Architekturentscheidungen.

## Lokal starten

Voraussetzungen: Node.js 22 oder neuer und npm. Rust 1.90.0 samt C-Compiler wird nur für die separate MLS-Erprobung gebraucht.

```sh
npm ci
npm run hooks:install
npm run types
npm run typecheck
npm test
npx wrangler d1 migrations apply DB --local
npm run dev
```

`GET /health` ist öffentlich. Gruppen-Routen benötigen ein vorab eingerichtetes Testgerät mit einem zufälligen 256-Bit-Bearer-Token. Nur der SHA-256-Hash dieses Tokens steht in D1; die Gültigkeit ist begrenzt. Es gibt keine öffentliche Registrierung oder Bootstrap-API.

## Relay-Grenzen

Das Relay kann Berechtigungen, Format, Größe und konkurrierende Schreibzugriffe prüfen. Es kann nicht beweisen, dass ein Base64-Payload wirklich verschlüsselt oder ein MLS-Mitgliedschaftswechsel erlaubt ist. Diese Prüfungen müssen die autorisierten Clients übernehmen.

Ereignisse bleiben maximal sieben Tage über die API abrufbar. Stündliche Bereinigung entfernt bis zu 1.000 abgelaufene Datensätze pro Lauf; Provider-Backups können länger bestehen. Die Gruppenrevision bleibt erhalten. Fehlende Historie führt zu HTTP 410 und erfordert einen noch zu implementierenden autorisierten Zustandsabgleich. Dies ist kein dauerhaftes Kalender-Backup.

Der Gruppenverlauf liefert maximal 100 Ereignisse pro Seite. Wiederholungen eines identischen Ereignisses sind während seiner Aufbewahrung idempotent. Nach Ablauf muss der Client mit einer aktuellen Revision und neuem Ereignis planen. Die Serverrevision schützt vor normalen Schreibkonflikten, nicht vor einem böswilligen Server.

## Cloudflare-Entwicklung

Die öffentliche `wrangler.jsonc` enthält ausschließlich eine lokale Platzhalter-Datenbank. Das Remote-Setup ist in [docs/development.md](docs/development.md) beschrieben. Deployment-Konfiguration, Zugangsdaten und lokale Zustände bleiben außerhalb von Git. Worker-Observability ist im DEV-Setup deaktiviert; der Anwendungscode protokolliert keine Request-Header oder Inhalte.

## Veröffentlichung und Prüfung

```sh
npm run check:secrets
npm run check:secrets -- --staged
```

Der lokale Guard prüft typische Geheimnisformate und Dateinamen; er ist keine Garantie. Zusätzlich läuft Gitleaks in GitHub Actions. Die CI führt Backend- und MLS-Tests aus. Es werden keine Deployment-Secrets in GitHub benötigt.

Öffentlicher Quellcode ermöglicht Prüfung, ersetzt aber keinen unabhängigen Sicherheitsaudit. Eine Open-Source-Lizenz ist noch nicht festgelegt; öffentliche Sichtbarkeit allein erteilt keine allgemeine Nutzungslizenz.
