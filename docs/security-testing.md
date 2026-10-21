# Sicherheitsregressionen und optionale AD-Prüfung

## Lokale Prüfung

`python -m pip install ".[dev]"` und `python -m pytest -q` führen die Regressionen aus.
Die TLS-Tests verwenden nur Loopback, eine pro Test neu erzeugte CA und synthetische
Schlüssel. Es werden keine produktiven Zugangsdaten oder externen LDAP-Server verwendet.

`tests/test_tls_integration.py` prüft einen gültigen Zertifikatspfad als Positivkontrolle,
eine nicht vertrauenswürdige CA, einen falschen Zertifikatshost und verweigertes StartTLS.
Beim verweigerten StartTLS muss der Server die Erweiterungsanfrage, aber keinen Bind sehen.
Die vorhandenen Bind-Reihenfolgetests decken zusätzlich Simple/NTLM und TLS-Optionen ab.
Das ersetzt keine echte NTLM-Interoperabilitätsprüfung gegen AD.

Einige Endpoint-Produkte ersetzen sogar Loopback-Zertifikate. Die Test-Fixture erkennt
das durch Vergleich des tatsächlich empfangenen Zertifikats mit dem erzeugten Zertifikat
und überspringt dann die drei Zertifikatstests mit ausdrücklichem Hinweis. Sie deaktiviert
keine Prüfung im Anwendungscode. Der eigentliche StartTLS-Verweigerungstest läuft weiter.
In diesem Fall die Zertifikatstests zusätzlich in einem isolierten Linux-Container oder
in der Linux-CI ausführen; Endpoint-Schutz muss dafür nicht abgeschaltet werden.

Die Exporttests prüfen auf Unix Dateimodus 0600 und Verzeichnismodus 0700. Auf Windows
liest der ACL-Test mit optional installiertem `pywin32` die geschützte DACL aus und erlaubt
nur SYSTEM und OWNER RIGHTS. Ohne dieses Testwerkzeug wird allein die ACL-Inspektion
übersprungen; die Anwendung selbst verwendet ausschließlich Windows-Standard-APIs.

## Optionale Samba/AD-Testumgebung

Eine separate, kurzlebige Samba-AD-Domäne `audit.example.test` ohne Vertrauensstellung,
Route oder Zugangsdaten zum produktiven AD verwenden. Ein Test-DC, ein reines Lesekonto,
mehrere synthetische Nutzer und verschachtelte/zyklische Gruppen genügen als Ausgangspunkt.
Domain-Admin-Zugangsdaten bleiben beim Provisionieren, nicht in ldapgrep-Konfigurationen.

Vor einem späteren Release manuell prüfen und Ergebnisse protokollieren:

1. Simple Bind über LDAPS sowie erfolgreiches StartTLS; RootDSE-/Schemaerkennung,
   Paging, AD-Mitgliedschaft und Gruppenbudgets.
2. NTLM über LDAPS/StartTLS mit `DOMAIN\\user`; gültiges und falsches Passwort,
   gesperrtes Konto und die vom Server erzwungenen Signing-/Channel-Binding-Vorgaben.
3. Unbekannte/abgelaufene CA, abgelaufenes Serverzertifikat, falscher SAN und verweigertes
   StartTLS: Verbindungsabbruch; keine Wiederholung ohne Prüfung oder ohne TLS.
4. Einschränkungen des Lesekontos und große/zyklische Gruppen; keine Attribute außerhalb
   der serverseitig erlaubten Sichtbarkeit erwarten.
5. Exporte und optionale Metadaten nur in privater Ablage; Testdomäne danach entfernen.

Dies ist ein dokumentierter optionaler Testplan, keine Behauptung über bereits ausgeführte
Samba-/Produktiv-AD-Tests. Ein CI-Job mit laufendem Samba-DC wurde nicht eingerichtet.
