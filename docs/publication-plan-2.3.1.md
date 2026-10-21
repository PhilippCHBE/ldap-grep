# Veröffentlichung 2.3.1: Umsetzung und offene Freigabe

Die ausgewählten Maßnahmen sind lokal umgesetzt. Das neue Ziel ist
https://github.com/PhilippCHBE/ldap-grep und wurde zunächst privat angelegt.
Ausgewählt ist zunächst ausschließlich eine Veröffentlichung auf GitHub; PyPI folgt später.
GitHub-Schutzregeln sind noch einzurichten; der PyPI-Upload bleibt deaktiviert.
Es wurde noch kein Release und kein PyPI-Paket veröffentlicht.

## Bereits umgesetzt

- F1–F10 stehen im CHANGELOG unter 2.3.1; Paket und CLI verwenden 2.3.1.
- Der Sicherheitsbericht ordnet die Korrekturen ausdrücklich Version 2.3.1 zu.
- Die GUI-Hilfe zeigt die Version.
- Paket-/Lizenzmetadaten verwenden den vorhandenen öffentlichen Handle statt des vollen
  Namens. Die persönliche Kontaktadresse wurde aus den Paketmetadaten entfernt.
- Das Konfigurationsbeispiel und EXAMPLE_CONFIG sind bereits gemeinsam korrigiert;
  ein Regressionstest lädt beide Profile und prüft ihre Gleichheit und sichere TLS-Werte.

## Veröffentlichung aus frischem Bestand

Ein normaler Clone enthält die bisherige erreichbare Historie. Damit kämen alte Autoren-
und Committerfelder einschließlich der früheren persönlichen Identität erneut mit.
Ein Clone des derzeitigen Remotes enthält außerdem die lokalen 2.3.1-Änderungen noch nicht.

Ausgewählt: Ein neues Repository mit genau einem bereinigten Initial-Commit
aus dem geprüften Stand 2.3.1 erzeugen. Die vorhandene private Entwicklungshistorie bleibt
unverändert als privates Archiv. Anschließend dieses neue Repository frisch klonen und nur
diesen Clone für Tests, Paketbau und spätere Veröffentlichung verwenden.

Der Initial-Commit verwendet den öffentlichen Handle PhilippCHBE und die GitHub-Noreply-Adresse
aus der über die öffentliche GitHub-API verifizierten Konto-ID. Die lokale Git-Konfiguration
des bisherigen Checkouts wurde ebenfalls auf diese Identität gesetzt; globale Einstellungen
und alte Commits bleiben unverändert.

Die lokale Vorbereitung verwendet `.private/publication/ldapgrep-2.3.1-source` für das
bereinigte Initial-Repository und `.private/publication/ldapgrep-2.3.1-clean` als frischen Clone.
Beide liegen außerhalb des freizugebenden Dateibaums. Der Clone bekommt die Hooks ebenfalls
lokal aktiviert; Git kopiert diese Einstellung beim Klonen nicht automatisch.

Zu kopieren: Anwendung, Tests, README, CHANGELOG, Lizenz, Beispielkonfiguration,
öffentliche Dokumentation und Workflows. Nicht kopieren: .git des alten Projekts,
.codex, Logs, private Konfiguration, Exporte, bestehende dist/build-Dateien und lokale
Werkzeugzustände. Vor Freigabe Dateibaum, Git-Objekte, Autorenfelder und neu gebaute Pakete prüfen.

Das bisherige Repository wurde auf GitHub in `ldap-grep-private` umbenannt. Das lokale
Git-Ziel des ursprünglichen Entwicklungscheckouts muss deshalb ebenfalls auf
https://github.com/PhilippCHBE/ldap-grep-private.git zeigen. Die bisherigen Homepage-,
Repository- und Issues-Links passen bereits zum neuen Ziel `PhilippCHBE/ldap-grep`.
Die private Entwicklungshistorie wird nicht in das neue Repository übernommen.

## Punkt 6: private Ablage und Schutz vor versehentlichem Commit

Private Ablage außerhalb des Checkouts:

| Inhalt | Windows | Linux/macOS |
|---|---|---|
| Konfiguration | %USERPROFILE%/.config/ldapgrep/ldap-grep.conf | ~/.config/ldapgrep/ldap-grep.conf |
| Passwortdatei | %LOCALAPPDATA%/ldapgrep/secrets/bind.secret | ~/.config/ldapgrep/secrets/bind.secret |
| Verzeichnisexporte | %LOCALAPPDATA%/ldapgrep/exports/ | ~/.local/state/ldapgrep/exports/ |
| Logs/Scanberichte | %LOCALAPPDATA%/ldapgrep/private-reports/ | ~/.local/state/ldapgrep/private-reports/ |

Die Exportpfade sind als Standard für CLI `--output auto` und GUI aktiv; explizite Ziele
bleiben wählbar. Konfiguration nutzt bereits die genannte Home-Konfigurationssuche.
Passwort-/Berichtsorte sind eine Ablageempfehlung, keine automatische Migration vorhandener Daten.
Exportverzeichnisse verwenden Unix 0700, Dateien 0600. Unter Windows wird eine geschützte
DACL ausschließlich für Eigentümer und SYSTEM gesetzt und im Test tatsächlich ausgelesen.
Kein Cloud-Sync-Ordner
als Standard für Produktivexporte. Bei nötigen Dateien im Checkout nur .private/ verwenden.

Aktive Ergänzungen in [.gitignore](../.gitignore), neben den bisherigen Konfigurationsregeln:

```gitignore
# Local secrets and work products
/.private/
/exports/
/private-reports/
.env
.env.*
!.env.example
*.local.conf
*.secret
*.key
*.p12
*.pfx
*.kdbx
id_rsa
id_ed25519
# Generated exports in every supported format
*_20??????_??????*.csv
*_20??????_??????*.json
*_20??????_??????*.tsv
*_20??????_??????*.ldif
*_20??????_??????*.yaml
*_20??????_??????*.txt
```

Bestehende Regeln für echte Konfiguration, CSV/JSON, dist/build und .codex bleiben bestehen.
Keine globale *.json-Regel: öffentliche Testdaten und Konfigurationen müssen versionierbar bleiben.
Absichtlich erforderliche private TLS-Testschlüssel bekommen ausschließlich eine konkrete,
überprüfte Ausnahme unter tests/fixtures; niemals den gesamten Testordner aus Secret-Scans ausschließen.
Ignore-Regeln entfernen keine bereits versionierten Daten und ersetzen keinen Scan.

### Aktivierter Secret-Scan

Gitleaks **8.30.1**, mit fest hinterlegten offiziellen SHA256-Prüfsummen für Windows/Linux x64.
Der Installer legt ausschließlich das verifizierte Binary unter `.private/tools/` ab. Keine Secrets an einen
Cloud-Scanner senden; lokale Prüfung und GitHub-CI im Repository genügen für diese Stufe.

1. Vor Commit: den Git-Index prüfen, damit genau der geplante Commit abgedeckt ist:
   `gitleaks git --pre-commit --staged --redact .`.
2. Vor Push: alle erreichbaren lokalen Branch-/Tag-Commits prüfen, zunächst vollständig:
   `gitleaks git --log-opts="--all" --redact .`. Spätere Optimierung auf die gepushten Bereiche
   nur, wenn neue Branches und Tags weiterhin sicher erfasst werden.
3. CI: denselben Scanner mit vollständiger Fetch-Historie bei Push/PR ausführen; den Status
   als erforderliche Prüfung für main und Releases konfigurieren.
4. Vor Erstveröffentlichung zusätzlich den vollständigen freizugebenden Dateibaum mit
   `gitleaks dir --redact <freigabeordner>` prüfen und die Paketarchive kontrollieren.

Native Git-Hooks unter `.githooks/` verwenden die Wrapper in `scripts/`. Nach jedem Clone:

```sh
python scripts/install_gitleaks.py
git config --local core.hooksPath .githooks
python scripts/secret_scan.py files
python scripts/secret_scan.py history
```

Die beiden Hooks sind im aktuellen Entwicklungscheckout lokal aktiviert. Der Commit-Hook scannt
den Index, der Push-Hook die Historie. Der Dateiscan prüft versionierte und nicht ignorierte
Publikationskandidaten; die Git-Scans schließen keine privaten Pfadnamen pauschal aus.
Ein fehlender Scanner oder ein Scanfehler blockiert die Operation mit Installationshinweis.
Ausgaben bleiben redigiert; Berichte nur in privater Ablage. Die Hooks selbst müssen nach jedem
neuen Clone installiert werden; sie werden durch das Klonen allein nicht aktiv.

Zusätzlich zu den Standardregeln eine LDAP-spezifische Regel für Passwortzuweisungen
(bind_password/BIND_PASSWORD/LDAPGREP_PASSWORD) und private Schlüssel einsetzen.
Die bekannten öffentlichen Demo-Credentials nur mit eng begrenzten Regel-/Wert-/Datei-Ausnahmen
zulassen. Die Namen-/E-Mail-Prüfung bleibt ein separater Datenschutzcheck: ein Secret-Scanner
erkennt weder zuverlässig alle Personenbezüge noch interne Organisationsdaten.

Der Praxistest mit einem generierten synthetischen LDAP-Passwort hat einen echten Commit
und einen Push in ein separates lokales Bare-Repository blockiert; das Ziel blieb ohne Refs.
Es wurden keine echten Tokens verwendet. Die freizugebenden Dateien und die bisherige
erreichbare Historie wurden zusätzlich ohne Secret-Fund gescannt.
Lokale Hooks sind übergehbar; serverseitige erforderliche CI-Prüfungen ergänzen sie.

## Punkt 7: ausgewählte Lösungen

| Thema | Umsetzung | Entscheidung/Status |
|---|---|---|
| Beispielkonfiguration | Bereits behoben, separate Kommentarzeilen; keine globale Inline-Kommentarentfernung, damit Passwortzeichen erhalten bleiben. | Kein erneuter Fix nötig. |
| Exportdateien | Private Standardablage, exklusive Neuerstellung, Symlinks/Reparse-Points ablehnen. Unix 0600/0700; Windows-ACL getestet. Mikrosekunden im automatischen Dateinamen. | Ausgewählt und umgesetzt; immer neuer Name, kein Überschreibmodus. |
| Exportmetadaten | Query-Kommentar standardmäßig aus, nur explizites Opt-in. JSON oder CSV anonymisiert keine Datensätze. | Ausgewählt und umgesetzt; kein zusätzlicher Supportexport. |
| Shell-Kommandos | PowerShell- und POSIX-Varianten korrekt quoten und beschriften. Apostrophe und Shell-Metazeichen sind getestet. Keine automatische Ausführung. | Beide Varianten ausgewählt und umgesetzt. |
| CI | Actions auf volle SHAs; contents:read als Standard. Separater Test-/Scan-/Buildjob und minimaler Publishjob, nur dort id-token:write. Stabile vX.Y.Z-Tags, Paketversion und main-Abstammung prüfen. | YAML umgesetzt. PyPI ausdrücklich auf später verschoben; Upload deaktiviert. |
| Tests | Echte Detailpanel-Assertion, lokale TLS-Tests mit Positivkontrolle, unbekannter CA, falschem Host und verweigertem StartTLS. Optionale Samba/AD-Anleitung. | Lokale Tests ausgewählt und umgesetzt; kein Samba-CI oder Produktiv-AD-Test. |

Die vollständige Suite bestand lokal mit **186 Tests und 3 expliziten TLS-Skips** unter
Windows (Avast ersetzt Loopback-Zertifikate) und **188 Tests und 1 Skip** unter Linux
(PowerShell nicht installiert). Sämtliche TLS-Fälle und Unix-Rechteprüfungen liefen unter
Linux erfolgreich; die Windows-DACL und PowerShell-Quoting-Prüfung liefen unter Windows.

Zertifikatfehler sollen zuerst auf CA-/Hostname-Konfiguration verweisen. --insecure bleibt
eine bewusst benannte Testausnahme; Fehlermeldungen sollen es nicht als Standardlösung empfehlen.
Branch-Protection muss im neuen Repository eingerichtet und geprüft werden; YAML allein
weist diese Plattformkonfiguration nicht nach. GitHub-Environment und PyPI Trusted Publisher
sind erst vor der späteren PyPI-Veröffentlichung einzurichten.
Der Upload ist zusätzlich gesperrt, solange die Repository-Variable `PYPI_PUBLISH_ENABLED`
nicht ausdrücklich `true` ist. Erst nach Wahl der Freigabeart und Einrichtung aller
Plattformregeln aktivieren. Empfohlen: im Environment `pypi` einen Required Reviewer
setzen und nur Release-Tags zulassen. Bei einem Einzelprojekt muss der eigene
Freigabeklick möglich bleiben; „Prevent self-review“ würde dafür einen zweiten Reviewer erfordern.

## Quellen für die vorgeschlagenen Werkzeuge

- [Gitleaks: offizielle Nutzung und Konfiguration](https://github.com/gitleaks/gitleaks)
- [Offizieller Gitleaks-Pre-Commit-Einstieg](https://github.com/gitleaks/gitleaks/blob/master/.pre-commit-hooks.yaml)
- [PyPI: Trusted Publishing ohne gespeicherten API-Token](https://docs.pypi.org/trusted-publishers/using-a-publisher/)
- [GitHub: Environments und Freigaberegeln](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
- [GitHub: sensible Daten und Historienbereinigung](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
