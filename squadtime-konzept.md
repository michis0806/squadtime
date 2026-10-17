# Squadtime – Konzept

Stand: 17.10.2026

## Problem & Idee

Kinder, die zusammen online spielen, finden schwer gemeinsame Zeiten. Sie nutzen verschiedene Plattformen (PS5, Switch, iPhone), und die Absprache läuft heute über verstreute Chats.

Squadtime löst das mit Gruppen, eingetragenen Spielzeiten und einer Ansicht, die den besten gemeinsamen Termin vorschlägt. Grundprinzip: **Eltern legen den Rahmen fest, Kinder planen frei darin.**

Zielgruppe sind zunächst Kinder von etwa 8 bis 15 Jahren und ihre Eltern; Jugendliche und Erwachsene können mit eigenem Konto dazukommen.

## Marktüberblick

Ähnliche Apps gibt es, aber keine ist für Kinder gemacht oder bindet Eltern ein. Die meisten sind kleine, junge Projekte für erwachsene Gamer.

| App | Plattform | Was sie kann | Was fehlt |
| --- | --- | --- | --- |
| [WellPlayed GG](https://mwm.ai/apps/wellplayed-gg/6758271397) | iOS | Spielbereit-Ping, Freunde per QR-Code, Sessions planen | Kein Kinderschutz, keine Eltern |
| [Squadling](https://peerpush.com/p/squadling) | Web | Gemeinsamer Gruppenkalender, Spielbereit-Signal | Keine App, kein Kinderschutz |
| [Party Planner](https://www.producthunt.com/@mikey963) | Web | Terminvorschläge, Zusage-Link ohne Account, iCal | Nur Terminfindung |
| Discord | alle | Server-Events, Chat | Kein Verfügbarkeitskalender ([Nutzerwunsch](https://support.discord.com/hc/sv/community/posts/5945192274967-Built-In-Scheduling-Calendar-Request)), erst ab 13 |

**Die Lücke:** eine kindgerechte, plattformübergreifende App mit Eltern-Rahmen, Spiele-Inventar und Bewertungen.

## Kernfunktionen (MVP)

Die erste Version konzentriert sich auf das Planen. Alles andere kommt später.

- **Kinderprofil ohne E-Mail:** Eltern legen Spitzname und Avatar aus fester Auswahl an, keine Fotos. Das Kind meldet sich per QR-Code aus der Eltern-App an, ohne Passwort.
- **Gruppen per Einladung:** Beitritt nur per Code oder QR-Code, keine öffentliche Suche. Maximal etwa 10 Mitglieder.
- **Verfügbarkeit:** feste Wochenzeiten („Mo/Mi 16–18 Uhr“) plus Abweichungen für einzelne Tage.
- **Überschneidungsansicht:** das Herzstück. Sie schlägt den besten Termin vor, z. B. „4 von 5 können Mi 17–18 Uhr, alle haben Mario Kart auf der Switch“.
- **Sessions:** Zeit, Spiel und Plattform vorschlagen; die anderen tippen „Dabei“ oder „Nicht dabei“.
- **„Bin online“-Knopf:** läuft nach 1 Stunde automatisch ab. Ersetzt vorerst eine Anbindung an PSN oder Nintendo, für die es keine offiziellen Schnittstellen gibt.
- **Schnellnachrichten statt Chat:** vorgefertigte Sätze wie „Komme 10 Min später“ oder „Wer hat Lust?“. Das vermeidet Moderations- und Mobbing-Probleme.

## Spiele-Inventar & Bewertung

Jedes Kind hat ein „Regal“ mit seinen Spielen pro Plattform und bewertet, wie gern es sie spielt. Beides fließt direkt in die Terminvorschläge ein.

**Inventar**

- Ablauf: Spiel suchen, Plattform antippen, fertig. Ein automatischer Import ist bei PlayStation und Nintendo nicht offiziell möglich.
- Cover kommen aus der Spieledatenbank IGDB (Twitch). Sie liefert auch quadratische Cover im Stil der Konsolen-Menüs, die gut in ein Regal-Layout passen.
- Die Stores selbst (PlayStation Store, eShop, Google Play) bieten keine offene Schnittstelle; Amazons API ist an das Partnerprogramm gebunden.
- IGDB ist für nicht-kommerzielle Nutzung kostenlos (4 Anfragen/Sekunde). Kommerziell braucht es eine Partnerschaft und einen sichtbaren Quellenhinweis ([Details](https://macmyths.com/apps/igdb/)).

**Bewertung: Wie gern spielst du das?**

- Vier kindgerechte Stufen statt Sterne: Lieblingsspiel, gern, geht so, gerade keine Lust. Jederzeit änderbar, weil sich Vorlieben schnell ändern.
- Bewertungen sieht nur die eigene Gruppe, es gibt keine öffentlichen Ranglisten.
- **Gruppen-Favoriten:** pro Gruppe die Spiele, die die meisten besitzen und am liebsten spielen.
- **Bessere Vorschläge:** die Überschneidungsansicht nimmt das Spiel, das die verfügbaren Kinder gemeinsam am liebsten spielen.
- **Entdecken:** „Drei aus deiner Gruppe lieben Minecraft, du hast es auch“. Bewusst ohne Kaufempfehlung oder Store-Links, damit kein Kaufdruck entsteht.

## Eltern-Funktion

Eltern geben Vertrauen über Freunde statt über einzelne Gruppen. Das Kind darf jeder Gruppe selbst beitreten, in der mindestens *n* freigegebene Freunde sind.

**So läuft ein Gruppenbeitritt ab**

1. Das Kind scannt einen Einladungscode.
2. Die App zählt die freigegebenen Freunde in der Gruppe.
3. Mindestens *n* gefunden: Das Kind ist sofort drin, die Eltern bekommen einen Hinweis.
4. Weniger als *n*: Die Eltern erhalten eine Anfrage und sehen die Mitglieder.

**Einstellungen pro Kind**

- **Modus:** Schwelle *n* (z. B. 1 oder 2), „immer frei“ oder „immer fragen“. So wächst die App mit dem Alter mit.
- **Freunde freigeben:** Wer sich persönlich per QR-Code scannt, zählt automatisch als freigegeben. Eltern können das abschalten und Freunde manuell bestätigen.
- **Zeitfenster:** z. B. „werktags 15–19 Uhr“. Das Kind plant nur innerhalb dieser Zeiten. Die Konsole selbst sperrt die App nicht; dafür verweist sie auf die Jugendschutz-Apps von Sony und Nintendo.
- **Altersfreigaben als Info:** Eltern sehen USK/PEGI der Spiele im Inventar (aus IGDB), ohne Sperre.
- **Wochenübersicht:** geplante Sessions auf einen Blick.
- **Profil löschen:** jederzeit, mit allen Daten.

## Kontotypen & Freigabe

Es gibt zwei Kontotypen: Kinderkonten, die Eltern verwalten, und Erwachsenenkonten mit eigener Anmeldung. Ein Kinderkonto lässt sich später in ein eigenständiges Konto umwandeln, ohne Daten zu verlieren.

| Kontotyp | Anmeldung | Rechte |
| --- | --- | --- |
| Kinderkonto | QR-Code-Kopplung durch die Eltern | Plant frei im Rahmen der Eltern-Einstellungen |
| Erwachsenenkonto | Eigene E-Mail mit Passkey oder Magic Link | Volle Rechte; kann zusätzlich die Eltern-Rolle für Kinderkonten übernehmen |

Die Eltern-Rolle ist also kein eigener Kontotyp, sondern eine Funktion eines Erwachsenenkontos. So können spielende Eltern die App auch selbst nutzen.

**Erwachsene in Gruppen mit Kindern**

- Gruppen nur für Erwachsene funktionieren ohne Einschränkungen.
- Einer Gruppe mit Kindern dürfen Erwachsene nur beitreten, wenn sie bei mindestens einem Kind der Gruppe als Elternteil oder freigegebener Kontakt eingetragen sind, z. B. ein älteres Geschwisterkind.
- In gemischten Gruppen sehen alle Kinder, dass ein Erwachsener Mitglied ist.

**Freigabe eines Kinderkontos in drei Stufen**

1. **Begleitet:** Gruppenbeitritt über die Freunde-Schwelle *n*, Zeitfenster aktiv.
2. **Frei:** Modus „immer frei“, keine Zeitfenster; Eltern sehen nur noch die Wochenübersicht.
3. **Eigenständig:** Die Eltern übergeben das Konto. Das Kind hinterlegt eigene E-Mail und Passkey und willigt selbst in den Datenschutz ein; der Eltern-Zugriff endet. Gruppen, Inventar und Bewertungen bleiben erhalten.

Da kein Geburtsdatum gespeichert wird, lösen Eltern die Stufen selbst aus. Optional können sie ein Erinnerungsdatum setzen, etwa zum 16. Geburtstag (Einwilligungsalter nach DSGVO in Deutschland).

**Folge für die Stores:** Mit Erwachsenenkonten ist die App keine reine Kinder-App. Statt der Apple-Kategorie „Kids“ wäre eine normale Kategorie mit passender Altersfreigabe sinnvoll; die Regeln ohne Werbung und Tracking gelten trotzdem weiter.

## Technik & Datensparsamkeit

Native Apps für iOS und Android sprechen mit einer gemeinsamen API in der EU. Für das Backend kommen drei Varianten infrage; gespeichert wird nur, was die Planung braucht.

**Architektur**

- **Apps:** nativ mit Swift/SwiftUI (iOS) und Kotlin/Jetpack Compose (Android). Eltern-, Kinder- und Erwachsenenansicht stecken in derselben App, getrennt über den Kontotyp.
- **Gemeinsamer API-Vertrag:** eine OpenAPI-Spezifikation, aus der die Netzwerkschicht beider Apps automatisch erzeugt wird. So bleiben die Apps konsistent.
- **Spiele-Proxy:** Der eigene Server fragt IGDB ab und cacht Cover. Die Geräte sprechen nie direkt mit Dritten; IGDB verlangt ohnehin einen Server-Proxy.
- **Push:** APNs für iOS, Firebase Cloud Messaging für Android, ausgelöst vom Backend.

**Backend-Varianten**

| Variante | Bausteine | Vorteile | Nachteile |
| --- | --- | --- | --- |
| **Hetzner** (Deutschland) | Cloud-Server mit Docker: Caddy, API (z. B. Kotlin/Ktor), PostgreSQL; Object Storage und Storage Box für Cover und Backups; optional Coolify für Deployments | Am günstigsten, volle Kontrolle, Server in Deutschland | Selbst Admin: Updates, Firewall, Backups, Datenbank-Betrieb |
| **Scaleway** (Frankreich) | Serverless Functions/Containers, Serverless SQL (PostgreSQL), Object Storage | Kein Serverbetrieb, echtes Postgres, klare EU-Regionen | Kosten weniger vorhersehbar, Push in kurzlebigen Funktionen etwas fummeliger |
| **Bunny.net** (Slowenien) | Edge Scripting, Bunny Database (SQLite-basiert), Bunny Storage (S3-kompatibel), Magic Containers | Am nächsten an Cloudflare Workers/D1/R2, sehr einfach | Edge läuft weltweit; EU-Beschränkung der Daten und AVV vorab prüfen |

Cloudflare selbst bietet für D1 und R2 EU-Datenhaltung, bleibt aber ein US-Unternehmen. **Empfehlung:** Scaleway, wenn kein Serverbetrieb gewünscht ist; Hetzner, wenn Admin-Arbeit kein Problem ist. Bunny vor einer Entscheidung mit einem Probe-Deployment testen. ([Bunny-Änderungsprotokoll](https://bunny.net/docs/changelog.md), [Scaleway Serverless](https://www.scaleway.com/en/build-scalable-applications-with-serverless/))

**Welche Daten gespeichert werden**

| Wer | Gespeichert | Nicht gespeichert |
| --- | --- | --- |
| Kind | Spitzname, Avatar-ID, Plattformen, Spiel-IDs mit Bewertung, Zeitslots | Klarname, Geburtsdatum, Fotos, Standort, Kontakte |
| Eltern | E-Mail-Adresse, Einstellungen | Adresse, Zahlungsdaten (im MVP) |

**Weitere Regeln**

- **Löschfristen:** vergangene Sessions nach 7 Tagen; der Online-Status wird nicht dauerhaft gespeichert.
- **Push-Nachrichten:** neutral formuliert („Neues in deiner Gruppe“), da sie über Apple- und Google-Server laufen.
- **Keine Werbung, kein Tracking:** keine Analyse- oder Werbe-SDKs. Google („Families“-Richtlinie) und Apple verlangen das für Apps mit Kindern als Nutzern.
- **Einwilligung:** über das Eltern-Konto nach Art. 8 DSGVO, bestätigt per E-Mail. Juristisch prüfen lassen.

## Offene Fragen & nächste Schritte

**Offene Fragen**

- Was passiert, wenn freigegebene Freunde eine Gruppe verlassen und die Schwelle unterschritten wird? Vorschlag: Das Kind bleibt drin, die Eltern bekommen einen Hinweis.
- Kostenlos, Einmalkauf oder Eltern-Abo? Davon hängt ab, ob eine IGDB-Partnerschaft nötig ist.
- Brauchen beide Elternteile Zugriff auf ein Kinderprofil?

**Nächste Schritte**

- [ ] Klickbaren Prototyp der Überschneidungsansicht bauen und mit Sohn und Freunden testen
- [ ] Andere Eltern der Gruppe nach Interesse und Bedenken fragen
- [ ] IGDB-Zugang anlegen und kommerzielle Bedingungen klären
- [ ] Datenschutz kurz juristisch prüfen lassen (Art. 8 DSGVO, Store-Richtlinien)
- [ ] Backend wählen: Hetzner, Scaleway oder Bunny, je mit kleinem Probe-Deployment
