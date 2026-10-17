# Entwicklungsbetrieb

## Konten und lokale Konfiguration

Cloudflare-Zugang erfolgt lokal über Wrangler OAuth (`npx wrangler login`). Für automatisches Deployment ist später ein begrenzter API-Token möglich; er gehört in einen Secret Store, nicht ins Repository. Kein automatisches Deployment ist eingerichtet.

Vor Remote-Befehlen mit `npx wrangler whoami` den richtigen Account prüfen. Account-ID und Datenbank-ID sind keine Authentisierungsgeheimnisse, bleiben hier aber aus Gründen der Trennung von Quellcode und Betrieb lokal.

Eine neue, dedizierte Datenbank `squadtime-dev` mit `--jurisdiction=eu` anlegen. Danach die nicht geheimen IDs in den Umgebungsvariablen `CLOUDFLARE_ACCOUNT_ID` und `SQUADTIME_D1_ID` bereitstellen und ausführen:

```sh
node scripts/configure-dev.mjs
npx wrangler d1 migrations apply DB --remote --config .local/wrangler.json
npx wrangler deploy --config .local/wrangler.json
```

`configure-dev.mjs` schreibt eine ignorierte Datei mit Zugriffsmodus 0600. Es überschreibt keine vorhandene Remote-Konfiguration. Ohne explizite IDs wird abgebrochen. Öffentliche Konfigurationen mit der Null-ID dürfen nicht für ein Remote-Deployment verwendet werden.

EU-Jurisdiktion begrenzt die D1-Datenbank; sie macht die gesamte Worker-Verarbeitung nicht automatisch EU-exklusiv. Keine Inhaltsdaten, Request-Bodys oder Authorization-Header protokollieren.

## Echter MLS-Transporttest

```sh
cd crypto/mls-spike
cargo build --locked --example relay_roundtrip
cd ../..
node scripts/smoke-remote.mjs
```

Dafür `SQUADTIME_DEV_URL` auf die zuvor bestätigte HTTPS-workers.dev-Adresse des DEV-Workers setzen. Das Skript prüft den lokalen Konfigurationsnamen, erzeugt einmalige Geräte-Tokens nur im Speicher und richtet kurzlebige synthetische Testdatensätze in der DEV-Datenbank ein. SQL-Dateien enthalten nur Hashes und technische IDs und werden nach Nutzung gelöscht. Keine Tokens gelangen in Kommandozeilen oder Logs.

Ein separater Rust-Prozess erzeugt eine echte MLS-Nachricht, der Test sendet ihren Chiffretext durch das Relay, liest ihn als berechtigter Empfänger zurück und lässt ihn im Rust-Prozess entschlüsseln. Zusätzlich werden fehlende Anmeldung, fremde Mitgliedschaft und Widerruf geprüft. Die Testdaten werden im `finally`-Block entfernt. Bei Abbruch/Netzwerkfehler können Testreste bleiben; Tokens laufen spätestens nach 15 Minuten ab und Ereignisse nach sieben Tagen.

Diese Prüfung ist ein Host-/Backend-Nachweis. Sie ersetzt keine nativen iOS-/Android-Tests, keine Geräte-Kopplung und keinen Recovery-Test.

## Prüfumfang vor echten Nutzerdaten

- Native Schlüsselablage, atomare Protokollzustände und Neustart-/Backup-Verhalten.
- Autorisierte Geräteaufnahme, Elternrechte, Mitgliedschaftsänderungen und Recovery.
- Der in docs/crypto-spike.md beschriebene Wiederzustellungsfall.
- Abuse-Schutz, Quotenmonitoring, operative Löschung/Backups und Deployment-Härtung.
- Gemeinsame Testvektoren für lokale Zeit-/Spielplanung, Zeitzonen und Sommerzeit.
