# Validierung des technischen Fundaments

Stand: 17.10.2026. Alle Prüfungen verwenden synthetische Daten.

## Lokal

- TypeScript-Typprüfung erfolgreich; Cloudflare-Laufzeittypen mit der gepinnten Wrangler-Version erzeugt.
- Relay-Tests gegen echtes lokales workerd/D1: Anmeldung, Gruppenrechte, Widerruf, konkurrierende Änderungen, Idempotenz, Ablauf, Paginierung und Größenlimits.
- MLS: drei Lifecycle-Tests, Formatierung und Clippy erfolgreich auf macOS arm64 mit Rust 1.90.0.
- Tests für Git-Hook und Secret-Guard prüfen insbesondere den vorgemerkten Git-Inhalt statt nur die Arbeitskopie.
- npm meldet für die gewählten Abhängigkeiten zum Prüfzeitpunkt keine bekannten Sicherheitslücken. Das ersetzt keine Quellcodeprüfung.

## Cloudflare DEV

Der Worker wurde in der vom Eigentümer ausgewählten privaten Cloudflare-Umgebung mit einer neuen D1-Datenbank angelegt. Die genaue Zuordnung bleibt in der ignorierten lokalen Deployment-Konfiguration.

Ein Live-Test hat eine frisch erzeugte MLS-Nachricht über HTTPS in D1 gespeichert, als zweites berechtigtes Testgerät abgerufen und im Rust-Prozess erfolgreich entschlüsselt sowie den MLS-Absender geprüft. Fehlende Anmeldung, fremde Gruppenmitgliedschaft, identische Wiederholung und Gerätewiderruf wurden ebenfalls geprüft. Die temporären Geräte, Gruppen und Ereignisse wurden anschließend entfernt.

Das belegt den Host-/Relay-Rundlauf. Es belegt **keine** native Geräte-Kopplung, vollständige Kontenidentität, echte Elternrechte, dauerhafte Schlüsselablage, Wiederherstellung oder fertige App-E2EE. Die MLS-Testidentitäten werden im Speicher vorab gegenseitig autorisiert. Die Bindung des inneren MLS-Gruppen-/Absenderkontexts an das produktive Kontenmodell ist noch zu implementieren.

## Offener kritischer Befund

Die getestete MLS-Konfiguration verbraucht bei fehlgeschlagener Authentisierung eine Nachrichtengeneration. Naive Wiederzustellung derselben ursprünglichen Nachricht funktioniert dann nicht. Details und Versionsbezug stehen in [crypto-spike.md](crypto-spike.md). Vor einem produktiven Client muss dieser Fall durch eine geprüfte Zustands-/Transaktionsstrategie oder eine andere geeignete Implementierung gelöst werden.
