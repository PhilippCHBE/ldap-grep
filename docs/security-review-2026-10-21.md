# Sicherheitsprüfung vor Veröffentlichung

## Nachtrag: F1–F10 in Version 2.3.1 behoben

Die Sicherheitsbefunde F1–F10 sind mit Version **2.3.1** behoben. Die Korrekturen sind
in der Arbeitskopie umgesetzt und unter 2.3.1 im CHANGELOG dokumentiert:

- F1: Kein automatischer öffentlicher Fallback; öffentliche Profile sind gegen Umgebungs-Credentials,
  Ziel-/Credential-Overrides und persönliche Passwortabfragen isoliert. Der Client kontrolliert
  die Identität öffentlicher Profile auch nach Änderungen im TUI-Formular.
- F2: Automatische Konfigurationssuche nur in Benutzer-/Systempfaden. Projektdateien erfordern
  `--config FILE` oder `LDAPGREP_CONFIG`.
- F3: Authentisierung verlangt LDAPS oder erfolgreiches StartTLS. Klartext nur mit ausdrücklichem
  `--allow-plaintext-auth` beziehungsweise `allow_plaintext_auth = true`. `--insecure` gibt
  Klartext nicht frei. Ungültige Schemes/Ports und URL-Credentials werden zurückgewiesen.
- F4: Ungültige boolesche Werte führen zu einem Fehler. Beispielkonfigurationen enthalten
  eigenständige Kommentarzeilen und aktivierte Zertifikatsprüfung, auch im FreeIPA-Preset.
- F5: Mindestversion und tatsächlich verwendeter Decoder auf pyasn1 0.6.4 aktualisiert;
  zusätzlicher Dependency-Audit in CI. Der erneute lokale Audit der 13 Projektabhängigkeiten
  meldet keine bekannten Schwachstellen.
- F6: CSV/TSV entschärft Formelpräfixe in Werten und Überschriften mit einem Apostroph,
  auch hinter führenden Leer-/Steuerzeichen. JSON/LDIF stehen für unveränderte Rohwerte bereit.
  Sämtliche CSV/TSV-Zellen sind gequotet, damit auch CR innerhalb einer Zelle bleibt;
  NUL wird als sichtbares `\x00` ausgegeben, einschließlich unter Python 3.9/3.10.
- F7: Custom, Demo und fehlgeschlagene Profilwechsel löschen alte Verbindungsdaten;
  Custom aktiviert Zertifikatsprüfung und übernimmt keine fremden TLS-/Passwortfelder.
- F8: Iterative, lazy Gruppenauflösung stoppt beim passenden Ergebnislimit. Gemeinsame Budgets
  begrenzen tatsächliche LDAP-Seitenabfragen, Einträge, Tiefe und Zeit auch in Fallbacks und
  memberof. Budgetüberschreitung endet mit einem ausdrücklichen Fehler über unvollständige
  Ergebnisse. Empfangstimeouts werden an die verbleibende Zeit angepasst; ein laufender
  Socket-Aufruf unterliegt dessen Timeout und keinem separaten Prozess-Watchdog.
- F9: Nicht vertrauenswürdige Inhalte werden als Text gerendert. Steuerzeichen und
  Bidi-Overrides werden in interaktiver Ausgabe sichtbar escaped; JSON bleibt gültig.
  Raw-Dateien und Pipes behalten ihre Daten. Die Regressionen prüfen tatsächliche CLI-/TUI-Pfade.
- F10: URL-Userinfo wird in server und config_server auch bei fehlerhaften Altwerten maskiert.
  Password und rohe URL-Felder erscheinen nicht im Settings-repr. --show-password gibt
  nur das ausdrücklich angeforderte Bind-Passwort frei.

Die Regressionstests stehen in `tests/test_security.py` und `tests/test_security_outputs.py`.
Das Offline-Reproduktionsskript führt jetzt diese aktuellen Sicherheitsregressionen aus.
README, Beispielkonfiguration und Changelog beschreiben die geänderte Bedienung.

Zusätzliche Härtungen für Version 2.3.1 nach dem Interview:

- Private Standardablage für Exporte; exklusive Neuerstellung, Ablehnung bestehender
  Ziele und Symlinks/Reparse-Points. Unix-Dateirechte 0600/Verzeichnisse 0700;
  geschützte Windows-DACL nur für Eigentümer und SYSTEM, experimentell ausgelesen.
- Abfragemetadaten standardmäßig aus; optional korrekt gequotete und beschriftete
  PowerShell-/POSIX-Befehle. Kein zusätzlicher Supportexport.
- Erweiterte Ignore-Regeln, lokal aktivierte blockierende Commit-/Push-Hooks und
  Gitleaks-CI. Scanner 8.30.1 mit geprüften Download-Prüfsummen. Der synthetische
  Praxistest blockierte beide Git-Operationen; Dateibaum-/Historienscans ohne Fund.
- Actions auf vollständige SHAs festgelegt; contents:read als Standard; getrennte
  Release-Prüfung und minimaler OIDC-Publishjob. Upload bis zur Plattform-Einrichtung
  zusätzlich über PYPI_PUBLISH_ENABLED deaktiviert. Freigabeart noch zu entscheiden.
- Wirkungsloses or True ersetzt; echte lokale TLS-Tests, sichere CA-/Hostname-Hinweise,
  Exportrechte- und Shell-Quoting-Tests. Optionaler Samba/AD-Testplan dokumentiert.

Abschlussprüfung: **186 Tests bestanden, 3 übersprungen** unter Windows/Python 3.13
mit pyasn1 0.6.4. Avast ersetzt lokale TLS-Zertifikate; die drei Zertifikatstests
erkennen dies ausdrücklich. Zusätzliche isolierte Linux-Prüfung: **188 bestanden,
1 übersprungen** (PowerShell dort nicht vorhanden); alle TLS- und Unix-Rechtefälle bestanden.
Wheel und Source-Archiv wurden lokal neu gebaut; Quellgleichheit, Decoder-Mindestversion,
enthaltene Sicherheitsregressionen und CI-YAML wurden geprüft. Es wurde nichts veröffentlicht.

Für Version 2.3.1 wurden der volle Name und die persönliche E-Mail-Adresse aus den
Paket-/Lizenzmetadaten entfernt; als öffentliche Identität dient der bestehende GitHub-Handle.
Die Veröffentlichung soll aus einem frischen, bereinigten Bestand erfolgen. Ein normaler
Clone übernimmt weiterhin die Git-Historie einschließlich alter Autorenfelder; das allein
entfernt die früheren Namens-/E-Mail-Nennungen nicht. Ausgewählt ist ein neues Repository
mit genau einem bereinigten Initial-Commit und danach ein frischer Clone. Der
[Veröffentlichungsplan](publication-plan-2.3.1.md) beschreibt Ablage, Hooks und noch offene
GitHub-/PyPI-Plattformregeln. Das bestehende Repository bleibt privat.
Die folgende Prüfung dokumentiert den ursprünglichen Zustand; ihre Angaben zu Testzahlen,
Dateibestand, Paketinhalt und unverändertem Anwendungscode sind historische Ausgangsbefunde.

---

Stand: 21.10.2026. Geprüfter Commit: 13a0dac76ab69313e2e71c88c3799ec348c85d76, Version 2.3.0.

**Empfehlung: vorerst privat lassen.** Mehrere bestätigte Fehler können LDAP-Zugangsdaten an unbeabsichtigte Server senden oder ihren Transport ungeschützt lassen. Im aktuell erreichbaren Quellstand wurden keine offensichtlichen produktiven Schlüssel oder Passwörter gefunden. Das ist keine Garantie, dass alle Daten zur Veröffentlichung bestimmt sind.

## Umfang und Nachweise

- Manuelle Prüfung von LDAP-Verbindung, Authentisierung, TLS, Konfiguration, Filtern, Gruppenauflösung, CLI/TUI, Ausgaben, Paketierung und beiden GitHub-Workflows.
- 28 aktuell versionierte Dateien; sechs von main erreichbare Commits. Zusätzlich alle 95 lokal vorhandenen Git-Objekte einschließlich 65 Blobs und drei nicht erreichbarer Commits auf verdächtige Inhalte und Metadaten untersucht.
- Git-Arbeitskopie war zu Beginn sauber. Binärvergleich mit Git wurde unter Berücksichtigung von CRLF/LF normalisiert.
- Entfernte Branches/Tags mit git ls-remote gelesen: ein Branch main, gleicher Commit; keine Tags angekündigt. Kein Fetch und keine Änderung am Remote.
- Aktuelle Tests: **55 bestanden in 26,92 Sekunden** unter Python 3.13.15.
- **14 zusätzliche Offline-Prüfungen** in [security-review-repro.py](security-review-repro.py) bestätigen die unten beschriebenen Verhaltensweisen. Aufruf: python docs/security-review-repro.py. Sie verwenden synthetische Zugangsdaten und stellen keine LDAP-Netzwerkverbindungen her. true bedeutet: das problematische Verhalten ist vorhanden.
- Bandit: 3.899 Codezeilen, 15 Hinweise mit niedriger Einstufung; keine mittleren/hohen Bandit-Treffer. Die wesentlichen Logikfehler wurden durch manuelle Prüfung gefunden. Schlüsselbezeichnungen, öffentliche Testpasswörter und Zufallszahlen für fiktive Beispieldaten sind hier überwiegend Fehlalarme beziehungsweise erwartetes Verhalten.
- pip-audit für 13 tatsächlich installierte direkte/transitive Laufzeitpakete: sechs Datenbankeinträge, nach Alias-/ID-Bereinigung **drei unterschiedliche bekannte Schwachstellen in pyasn1 0.6.3**. Prüfung über den Windows-Vertrauensspeicher; Zertifikatsprüfung blieb aktiv. Kein vollständiger Audit aller möglichen durch Versionsbereiche erlaubten Installationen.
- Vorhandenes Wheel und Source-Archiv geprüft: jeweils zehn Python-Quelldateien stimmen mit der Arbeitskopie überein; keine echten Konfigurationen, Logs, .git- oder Legacy-Dateien enthalten. Das SVG enthält keine Script-Elemente, Event-Handler oder externen href/src-Verweise.

## Priorisierte Befunde

| ID | Priorität | Befund | Fundstellen |
|---|---|---|---|
| F1 | P1 / hoch | Öffentliche Testprofile übernehmen vorhandene Zugangsdaten | ldapgrep/config.py:414,420 |
| F2 | P1 / hoch | Automatisch geladene lokale Konfiguration kann Zugangsdaten umleiten | ldapgrep/config.py:242,279,414 |
| F3 | P1 / hoch | Passwortanmeldung über unverschlüsseltes LDAP zugelassen | ldapgrep/client.py:430,444,467 |
| F4 | P1 / hoch | Unbekannte boolesche Werte schalten TLS-Prüfung still ab | ldapgrep/config.py:163,199 |
| F5 | P1 / hoch | Bekannte DoS-Schwachstellen in installiertem ASN.1-Decoder | pyproject.toml:23; requirements.txt:3 |
| F6 | P2 / mittel | CSV/TSV übernimmt Formeln aus LDAP unverändert | ldapgrep/format.py:357 |
| F7 | P2 / mittel | TUI-Custom-Auswahl behält fremde Zugangsdaten und TLS-Checkbox | ldapgrep/tui.py:143,162,171 |
| F8 | P2 / mittel | Gruppenlimit begrenzt nachgelagerte Arbeit nicht zuverlässig | ldapgrep/client.py:1073,1079,1104 |
| F9 | P2 / mittel | LDAP-Inhalte können Darstellung manipulieren oder Ausgabe abbrechen | ldapgrep/cli.py:553,562,569,753; ldapgrep/format.py:547 |
| F10 | P3 / niedrig | Konfigurationsausgabe maskiert eingebettete URL-Zugangsdaten nicht | ldapgrep/config.py:97,178; ldapgrep/cli.py:587 |

P1: vor Veröffentlichung beheben. P2: vor breiter Nutzung beheben. P3: Härtung beziehungsweise Sonderfall mit geringerer Eintrittswahrscheinlichkeit. Einstufungen berücksichtigen dieses lokale Verwaltungswerkzeug; keine ungeprüften CVSS-Werte für eigene Befunde vergeben.

### F1 – Vermischung mit öffentlichen Testservern

Wenn kein Server gesetzt ist, ergänzt load_settings() fehlende Felder aus dem öffentlichen forumsys-Profil einzeln. Bereits gesetzte bind_dn und bind_password bleiben erhalten. Mit gesetztem LDAPGREP_BIND_DN und LDAPGREP_PASSWORD, aber fehlendem LDAPGREP_SERVER, entsteht damit eine Anmeldung der echten Identität am öffentlichen Server über Port 389. Auch ein allein gesetztes Passwort kann mit dem öffentlichen Demo-Bind-DN kombiniert werden. Der Hinweis auf den Fallback ist keine Zustimmung und wird mit --quiet unterdrückt.

Auch explizit gewählte öffentliche Profile werden anschließend durch globale LDAPGREP_*-Variablen überschrieben. Eine in der Umgebung vorhandene produktive Passwortvariable kann dadurch beispielsweise beim FreeIPA-Testprofil landen. Das eingebaute Profil schaltet zusätzlich die Zertifikatsprüfung ab.

**Korrektur:** Bei fehlendem Server abbrechen oder ausschließlich die netzwerkfreie Demo starten. Öffentliche Profile ausdrücklich auswählen lassen und ihre Credentials vollständig gegen globale produktive Credentials isolieren. Niemals ein teilweise befülltes produktives Settings-Objekt mit öffentlichen Defaults ergänzen. Regressionen für vollständige und teilweise gesetzte Zugangsdaten aufnehmen.

### F2 – Konfigurationsdatei im Arbeitsverzeichnis als Vertrauensgrenze

Die Suche priorisiert das aktuelle Arbeitsverzeichnis, dann Skriptverzeichnis und dessen Elternordner, vor persönlichen Einstellungen. Ein fremdes Checkout oder gemeinsam beschreibbarer Ordner kann eine ldap-grep.conf mit eigener server-Adresse enthalten. Danach ergänzte Umgebungsvariablen oder die Passwortabfrage liefern dem fremden Ziel die Credentials. Selbst ein gültiges LDAPS-Zertifikat des fremden Ziels verhindert diese Umleitung nicht.

**Voraussetzung:** Der Nutzer führt das Werkzeug in einem fremden Ordner aus oder ein anderer Benutzer kann einen automatisch berücksichtigten Konfigurationsort beschreiben. Es ist kein Zugriff auf die bestehende persönliche Konfiguration nötig.

**Korrektur:** Standardmäßig nur vertrauenswürdige Benutzer-/Systempfade lesen. Projektkonfiguration nur über explizites --config laden; alternativ Herkunft und neuen Zielhost vor Übernahme von Credentials verbindlich bestätigen. Credentials an Zielhost beziehungsweise Profil binden. --no-config beseitigt diesen lokalen Dateipfad, aber nicht F1 oder Profilüberschreibungen durch die Umgebung.

### F3 – Unverschlüsselte Passwortanmeldung

Ein nackter Host oder ldap:// führt ohne start_tls zu SIMPLE-Bind über Klartext. tls_verify=True schützt nur tatsächlich verwendetes TLS. Die Verbindung fordert weder TLS noch eine ausdrückliche Freigabe unsicheren Transports. Die Offline-Reproduktion zeigt, dass bind() ohne vorheriges start_tls() aufgerufen wird.

Zusätzlich akzeptiert parse_server_url() unbekannte Schemes: https://audit.example wird als LDAP-Ziel ohne TLS interpretiert. Ungültige Portangaben werden still auf den Standardport zurückgeführt. Das begünstigt überraschende Sicherheitsänderungen bei Fehlkonfiguration.

**Korrektur:** Authentisierten Klartext-Bind standardmäßig verweigern; LDAPS oder erfolgreiches StartTLS verlangen. Eine bewusst benannte Ausnahme für isolierte Testumgebungen kann gesondert angeboten werden. Nur ldap und ldaps akzeptieren, Port-/Hostfehler strikt zurückweisen. NTLM nicht als gleichwertigen Ersatz für einen geschützten Transport behandeln.

### F4 – TLS-Konfiguration scheitert unsicher

parse_bool() erkennt nur eine Liste positiver Werte; alles andere wird False. Ein Tippfehler wie tls_verify=tru deaktiviert die Zertifikatsprüfung ohne Fehlermeldung. Dasselbe passiert mit true gefolgt von einem Inline-Kommentar, weil ConfigParser hier Inline-Kommentare nicht entfernt.

**Korrektur:** Anerkannte positive und negative Werte explizit behandeln und jeden unbekannten Wert mit ConfigError zurückweisen. Konfigurationskommentare eindeutig definieren; keine pauschale Behandlung, die zulässige Passwortzeichen abschneidet. Tests für Schreibfehler und alle TLS-Schlüssel ergänzen.

### F5 – Verwundbare Abhängigkeit

Installiert ist pyasn1 0.6.3; deklariert wird nur >=0.4.8. Der Bereich erlaubt diese und weitere ältere verwundbare Versionen. pip-audit meldet drei unterschiedliche Advisories, jeweils mit Fix 0.6.4:

- [CVE-2026-59884 / lange ASN.1-Tags](https://github.com/pyasn1/pyasn1/security/advisories/GHSA-m4p7-r5rc-7g4j): manipulierte BER-Tags können hohe CPU-Last und unerwartete Fehler auslösen.
- [CVE-2026-59885 / OID-Verarbeitung](https://github.com/pyasn1/pyasn1/security/advisories/GHSA-8ppf-4f7h-5ppj): ungünstige Verarbeitung langer OID-Folgen ermöglicht Ressourcenerschöpfung.
- [CVE-2026-59886 / REAL-Konvertierung](https://github.com/pyasn1/pyasn1/security/advisories/GHSA-hm4w-wwcw-mr6r): bestimmte numerische Konvertierungen können übermäßig Ressourcen beanspruchen. Die konkrete REAL-Erreichbarkeit im LDAP-Pfad ist nicht nachgewiesen.

Ein schädlicher LDAP-Endpunkt oder manipulierter ungeschützter Transport liefert fremde ASN.1-Daten an den Client. Ein vollständiger Exploit gegen den Netzwerkdecoder wurde bewusst nicht ausgeführt; Paketversion und Advisory-Betroffenheit sind verifiziert.

**Korrektur:** Mindestversion in beiden Abhängigkeitsdefinitionen auf mindestens 0.6.4 anheben, tatsächlich verwendete Umgebung aktualisieren und mit ldap3 sowie den unterstützten Python-Versionen prüfen. Automatischen Dependency-Audit in CI aufnehmen.

### F6 – CSV-/TSV-Formelinjektion

csv.DictWriter übernimmt flatten_value() ohne Formelschutz. Ein durch LDAP geliefertes Namens-, Beschreibungs- oder sonstiges Feld mit =1+1 bleibt als Formel erhalten. Das reguläre CSV-Quoting schützt nicht vor Interpretation durch Tabellenkalkulationen. Angreifer müssten einen exportierten LDAP-Wert beeinflussen; die Auswirkung hängt vom späteren Importprogramm und dessen Schutzmaßnahmen ab.

**Korrektur:** Einen dokumentierten tabellenkalkulationssicheren Export mit Neutralisierung von Formelpräfixen und relevanten führenden Steuerzeichen bereitstellen. Datengetreuen Rohdatenexport gesondert kenntlich machen. Auch Spaltenüberschriften und mehrwertige Felder berücksichtigen. Die Reproduktion verwendet ausschließlich eine harmlose Rechenformel.

### F7 – TUI-Custom übernimmt bestehende Formulardaten

Beim Wechsel auf Custom wird self.current zurückgesetzt, die sichtbaren Server-, Passwort- und TLS-Felder jedoch nicht. _collect() übernimmt diese alten Werte zurück. Nach FreeIPA → Custom bleiben beispielsweise das öffentliche Ziel, ein Passwort und deaktivierte Zertifikatsprüfung sichtbar und wirksam. Das kann beim anschließenden Eingeben eigener Credentials zu einer unbeabsichtigten Verbindung führen. Die Auswahl allein sendet noch keine Daten; dazu muss Connect ausgelöst werden.

**Korrektur:** Custom über _fill(fresh) vollständig initialisieren. Bei Zielwechsel Credentials leeren und TLS-Verifikation wieder aktivieren. StartTLS-/CA-Einstellungen sichtbar oder nachvollziehbar halten und den vollständigen Serverwechsel testen.

### F8 – Ergebnislimit ist kein verlässliches Arbeitsbudget

Die member-/uniqueMember-Fallback-Auflösung lädt sämtliche Mitglieder einzeln; das limit wird erst auf das fertige Ergebnis angewandt. Die Reproduktion fordert limit=1 an und beobachtet drei Einzelabfragen für drei Mitglieder. Rekursive Aufrufe setzen limit=0; eine große oder tief geschachtelte Gruppierung kann deshalb viele Abfragen, hohe Speichernutzung und große Rekursionstiefe verursachen. Besuchte Gruppen werden bereits erfasst, einfache Zyklen sind damit begrenzt.

**Korrektur:** Globales Budget für Einträge, LDAP-Abfragen, Rekursionstiefe und Gesamtdauer durch alle Fallback-/Rekursionspfade weiterreichen. Frühzeitig abbrechen und unvollständige Resultate kennzeichnen. Ein Ausgabelimit und ein Arbeitsbudget sollten unterschiedliche, dokumentierte Bedeutungen haben.

### F9 – Nicht vertrauenswürdige Darstellung

cmd_tree() setzt Namen und Beschreibungen direkt in Rich-Markup ein; mehrere Fehlerausgaben machen dasselbe. Eine Beschreibung mit nicht passenden Abschlusstags kann beim Rendern MarkupError verursachen. Andere Tags können Inhalte optisch verändern. Die Reproduktion zeigt den Rich-Parserfehler für genau dieses Zusammensetzungsmuster; ein vollständiger cmd_tree()-Durchlauf mit fremdem Server wurde nicht ausgeführt.

Für list-/dn-Ausgaben schreibt _print_plain() die Zeichenfolge direkt nach stdout. Ein im DN enthaltener ESC-Steuerbefehl bleibt erhalten. Eine entsprechende Wirkung auf bestimmte Terminalprogramme wurde nicht ausgenutzt. Daraus folgt keine nachgewiesene Codeausführung.

**Korrektur:** Untrusted Inhalte als rich.text.Text beziehungsweise konsequent escaped rendern. Steuerzeichen bei interaktiver Terminalausgabe sichtbar darstellen; maschinenlesbare Dateiformate getrennt behandeln, damit die Datenbedeutung erhalten bleibt. Tests für Sonderklammern, neue Zeilen und ESC ergänzen.

### F10 – Unvollständige Geheimnismaskierung

Settings.to_dict() maskiert nur bind_password. Enthält server eine URL mit user:password@host, landet das Passwort unverändert in server und gegebenenfalls config_server. Der Parser akzeptiert diese Form, obwohl die Credentials daraus nicht zur Anmeldung übernommen werden. ldapgrep config kann dadurch eine irrtümlich so konfigurierte URL veröffentlichen.

**Korrektur:** URL-Userinfo als ungültige Konfiguration ablehnen oder in sämtlichen Diagnosefeldern entfernen. Zugangsdaten ausschließlich in den dafür vorgesehenen Feldern akzeptieren. --show-password bleibt eine ausdrücklich gewählte Ausnahme.

## Daten, Historie und Veröffentlichung

### Aktueller Stand und normal erreichbare Historie

- Keine offensichtlichen produktiven API-Tokens, privaten Schlüssel oder echten Bind-Passwörter in den geprüften erreichbaren Dateien gefunden. Passwortfunde betreffen fiktive Offline-Daten, Testfälle, Platzhalter und eingebaute öffentliche Testprofile.
- Die Beispieldaten verwenden example.com beziehungsweise daraus abgeleitete Demo-Adressen. Der Screenshot wird laut Generator aus dem Offline-Demo-Verzeichnis erzeugt. Keine offensichtlichen produktiven Verzeichnisexporte im versionierten Bestand gefunden.
- Dein voller Name und deine private Gmail-Adresse stehen in pyproject.toml:13, Paketmetadaten sowie den Autoren-/Committerfeldern der erreichbaren Commits. Der Name erscheint außerdem in der Lizenz. Das ist eine bewusste Veröffentlichungsentscheidung, kein Geheimnisfund. Bei gewünschter E-Mail-Privatsphäre Paketkontakt und gesamte zu veröffentlichende Git-Historie berücksichtigen; eine Änderung nur am letzten Commit genügt nicht.
- Commit-Nachrichten enthalten Co-Author-Angaben und Hinweise auf die frühere Skriptbezeichnung. Sie enthalten in der überprüften erreichbaren Historie keine offensichtlichen produktiven Credentials.

### Lokal verbliebene Altstände

Drei Commit-Objekte sind von aktuellen Referenzen nicht erreichbar: d389279…, d62d802… und f688db5…. Zwei enthalten frühere berufliche Autoren-/Committeradressen und legacy/ldap-getGroupMembers.py. Der Legacy-Blob 50bb0b3… enthält dieselbe berufliche Kontaktadresse, eine konkrete Büroanschrift in einem Hilfetext und frühere hartkodierte LDAP-Einstellungen. Der Passwortwert sieht nach einem Platzhalter aus; seine frühere Verwendung als echtes Passwort ist damit weder bewiesen noch ausgeschlossen.

Diese Altobjekte werden beim gewöhnlichen Push von main nicht automatisch mitübertragen. Ein vollständiges Kopieren des Projektordners einschließlich .git würde sie jedoch offenlegen. Eine Umschaltung eines bestehenden GitHub-Repositories auf public ist auch keine Garantie, dass zuvor hochgeladene Altobjekte, PR-Referenzen, Caches oder Artefakte verschwunden sind. Deren serverseitige Existenz wurde hier nicht geprüft.

**Empfehlung:** Veröffentlichbaren Inhalt aus einem frischen Clone der bereinigten Referenzen kontrollieren. Bei Veröffentlichung desselben bestehenden Repositories dessen frühere Uploads und versteckte Referenzen gesondert prüfen. Kein weiterer History-Rewrite, Force-Push, Löschen oder Garbage-Collection wurde ausgeführt.

### Nur lokal vorhandene Dateien

.codex/logs, dist und ldapgrep.egg-info sind durch .gitignore ausgeschlossen und aktuell nicht versioniert. Die lokalen Logs enthalten frühere Befehle und Verweise auf Legacy-Dateien; sie gehören nicht in ein veröffentlichtes Ordnerarchiv. Es liegt aktuell keine echte LDAP-Konfiguration im Projektbaum. Andere persönliche Konfigurationen außerhalb des Projekts wurden nicht durchsucht.

.gitignore schützt gegen die beiden üblichen echten Konfigurationsnamen und *.secret, aber nicht allgemein gegen .env-Dateien, beliebig benannte Exporte oder private Schlüsseldateien. Die Exportmuster erfassen nur bestimmte datierte CSV-/JSON-Dateinamen; YAML, LDIF, TSV und frei benannte Ausgaben könnten versehentlich committed werden. Künftig passende private Ablageorte/Ignore-Regeln und einen Secret-Scan vor Commit und Push einführen.

## Weitere Qualitätsprobleme und Härtung

- **Beispielkonfiguration ist derzeit nicht direkt nutzbar:** auth = simple gefolgt von einem Semikolon-Kommentar wird als kompletter Auth-Wert gelesen und mit ConfigError zurückgewiesen. Dasselbe Format betrifft mehrere weitere Felder. Reproduktion vorhanden. Beispiel und eingebettetes EXAMPLE_CONFIG gemeinsam korrigieren und einen Lade-Test für das mitgelieferte Beispiel hinzufügen.
- **Exportdateien:** format.py:558 verwendet normales open(..., 'w'). Auf Unix sind Rechte vom umask abhängig; bestehende Dateien werden überschrieben und Symlinks verfolgt. Die konkrete Windows-/Unix-Rechtewirkung wurde nicht experimentell bewertet. Für sensible Verzeichnisexporte restriktive Neuerstellung, kontrolliertes Überschreiben und eine geeignete Ablage vorsehen.
- **Exportmetadaten:** TUI-Exporte können Servername, Base-DN und LDAP-Filter im Kommentar enthalten. Raw-Ansichten können alle für das Bind-Konto lesbaren Attribute ausgeben. Vor Weitergabe an Issues/Support bereinigen. Dies ist grundsätzlich vorgesehene Funktionalität, keine nachgewiesene ACL-Umgehung.
- **Kopierbare Shell-Kommandos:** tui.py:775 und :793 schließen variable Werte nur in einfache Anführungszeichen ein. Ein Apostroph in einem Verzeichnisnamen kann das ausgegebene Beispielkommando ungültig machen beziehungsweise beim späteren Kopieren die Shell-Struktur ändern. Das Programm führt diesen Text selbst nicht aus. Plattformgerechtes Quoting oder rein beschreibende Ausgabe verwenden.
- **CI:** Actions werden per beweglichem Versions-Tag eingebunden. Vollständige Commit-SHAs, minimale contents:read-Rechte, ein eigener minimaler Publish-Job für id-token:write und geprüfte Veröffentlichungsbedingungen reduzieren Supply-Chain-Risiken. PyPI Trusted Publishing vermeidet bereits gespeicherte API-Tokens. GitHub-Environment-Schutzregeln und Branch-Protection sind aus den YAML-Dateien nicht erkennbar und wurden nicht über die Plattform geprüft.
- **Tests:** Gegenwärtige Tests prüfen vorwiegend Funktionalität. In test_tui.py:34 macht or True eine Assertion wirkungslos. Produktions-AD, echte Zertifikatfehler, falscher Zertifikathost, verweigertes StartTLS und NTLM-Varianten sind durch diesen Audit nicht praktisch gegen einen AD-Server getestet. Bei eigenen TLS-Fehlern keine automatische Empfehlung zum Abschalten der Prüfung als Standardlösung geben.

## Bereits vorhandene Schutzmaßnahmen

- Normale Suchwerte werden mit escape_filter_chars() escaped; auch Gruppen-DNs und memberUid werden in den relevanten Filterpfaden escaped. Kein bestätigter LDAP-Injection-Befund in diesen Pfaden. Raw-Filter sind eine bewusst angebotene Eingabe des ausführenden Nutzers.
- auto_referrals=False verhindert automatische Anmeldungen an LDAP-Referral-Zielen.
- read_only=True ist für die LDAP-Verbindung gesetzt. Im Anwendungscode keine LDAP-Schreiboperationen und keine direkten eval/exec/os.system/subprocess-Aufrufe gefunden.
- TLS-Verifikation ist im Settings-Default aktiv. ldap3 2.9.1 prüft den Zertifikatshost separat; dessen internes check_hostname=False allein wurde daher nicht als Hostname-Bypass gewertet.
- StartTLS-Fehler des installierten ldap3 werden grundsätzlich als Ausnahme behandelt. Aus dem unbeachteten booleschen Rückgabewert allein wurde kein praktisch nachgewiesener Downgrade behauptet.
- Gruppenzyklen werden durch Besuchsmengen begrenzt; automatische Dateinamen filtern Pfadtrennzeichen.

## Vorgehen vor dem Public-Schalten

1. F1–F5 beheben und die Reproduktionen in Regressionstests mit sicherem Sollverhalten überführen.
2. F6–F9 und das fehlerhafte Konfigurationsbeispiel korrigieren; Zielwechsel und sensible Exporte praktisch prüfen.
3. Über die Veröffentlichung der privaten Kontaktadresse entscheiden und den finalen Git-/Paketbestand erneut prüfen.
4. Den öffentlich sichtbaren Bestand aus frischem Clone verifizieren; beim bestehenden Remote zusätzlich alte PRs, Releases, Actions-Artefakte und frühere History-Bereinigungen kontrollieren.
5. Aktualisierte Abhängigkeiten, vollständige Tests und Dependency-/Secret-Scan in CI prüfen; anschließend eine eigene Entscheidung zum Public-Schalten treffen.

Es wurden ausschließlich dieser Bericht und das Offline-Reproduktionsskript im Projekt ergänzt. Anwendungscode, Dependencies, Git-Referenzen und Repository-Sichtbarkeit wurden nicht geändert. Sicherheitswerkzeuge wurden isoliert im temporären Verzeichnis installiert. Die Prüfung liefert konkrete Befunde mit nachvollziehbaren Grenzen; sie ersetzt keinen Nachweis über nicht zugängliche historische Serverdaten.
