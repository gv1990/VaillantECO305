# Vaillant ECO305 für IP-Symcon 9

Version 0.8 ist ein **rein passiver** Decoder für Vaillant-eBUS-Telegramme,
die über einen ESERA ECO305 im Enhanced Mode per TCP an IP-Symcon gelangen.

## Sicherheitsgrenze

- kein `EnableTest`
- keine Pumpenbefehle
- keine Ventilbefehle
- keine Kompressorbefehle
- keine Sicherheits-/Servicebefehle
- keine generische Raw-Send-Funktion

Version 0.8 enthält absichtlich **keinen** Aufruf von `SendDataToParent()`.
Kompressordaten werden nur ausgewertet, wenn sie bereits auf dem Bus vorhanden
sind.

Die Heizkurve wird in Version 0.8 nur gelesen. Eine spätere Schreibfunktion
soll ausschließlich über eine explizite Whitelist für die Heizkurve erfolgen.

## Archiv

Alle vom Modul angelegten Statusvariablen werden automatisch im vorhandenen
IP-Symcon Archive Control aufgezeichnet und für die Visualisierung aktiviert.
Die Archivierung erfolgt ausschließlich lokal in IP-Symcon und erzeugt keinen
eBUS-Verkehr.

Die passiven Diagnosewerte für B5-24/B5-1A werden absichtlich nicht archiviert,
da sie bei jedem Telegramm aktualisiert werden und sonst unnötig viele
Archiveinträge erzeugen würden. Version 0.8 zeigt zusätzlich das zuletzt
beobachtete B5-1A-Telegramm als Hex-Text an, sammelt bis zu 32 verschiedene
B5-1A-Requesttypen und trennt den beobachteten aroTHERM/VWZ-Regelkreis in die
Untertelegramme `32` bis `36`. Für jeden dieser Typen wird Request und komplette
letzte Antwort gespeichert. Auch diese Diagnose ist rein passiv und sendet
keine Abfragen auf den eBUS.

Zusätzlich sammelt Version 0.8 vorhandene B5-14-Telegramme. Dabei werden die
gesehenen IDs, die jeweilige Häufigkeit sowie Request und letzte vollständige
Antwort protokolliert. Es wird kein Testmodus aktiviert und kein B5-14-Request
vom Modul erzeugt.

Version 0.8 enthält außerdem einen passiven Änderungsrekorder für die
B5-1A-Untertelegramme `32` bis `36`. Das gespiegelte Zählerbyte wird ignoriert.
Für tatsächlich geänderte Nutzbytes bleiben letzte Änderung, Minimum, Maximum
und Änderungshäufigkeit erhalten, auch wenn die Anlage anschließend wieder in
den vorherigen Betriebszustand zurückkehrt.

## Verbindung

Das Modul ist als Device für den nativen IP-Symcon Client Socket ausgelegt.
Für die vorhandene Anlage ist der Client Socket auf ECO305 `172.30.10.239:5001`
konfiguriert.

## Enthaltene Decoder

- ECO305 Enhanced Mode inklusive persistentem Telegrammpuffer
- B5 24 sensoCOMFORT/Systemdaten
- B5 1A HMU Normal-Live-Monitor

## Bereits abgebildete Werte

- Außentemperatur
- Wasserdruck
- System-Vorlauf
- Energie Heizung / Warmwasser
- Warmwasser Soll / Ist / Vorlauf
- HK1 Vorlauf Soll / Ist
- Heizkurve HK1
- HMU Vorlauf-/Quellentemperaturen
- Wärme-/Aufnahmeleistung
- Kompressorauslastung (nur lesen)
- Durchfluss Heizkreis
- HMU Drücke
