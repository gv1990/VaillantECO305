# Vaillant ECO305 für IP-Symcon 9

Version 1.4 decodiert Vaillant-eBUS-Telegramme, die über einen ESERA ECO305
im Enhanced Mode per TCP an IP-Symcon gelangen. Durchfluss und
Kompressorauslastung werden weiterhin rein passiv empfangen. Optional können
fest eingebaute HMU-Telemetrieregister ausschließlich lesend abgefragt werden.

## Sicherheitsgrenze

- kein `EnableTest`
- keine Pumpenbefehle
- keine Ventilbefehle
- keine Kompressorbefehle
- keine Sicherheits-/Servicebefehle
- keine generische Raw-Send-Funktion

Die aktive Abfrage besitzt keine frei eingebbaren Telegramme. Sie ist im Code
fest auf offizielle HMU-Leseregister begrenzt. Dazu gehören:

- `B5 1A / 05 00 32 23`: aktuelle Umweltleistung
- `B5 1A / 05 00 32 24`: aktuelle elektrische Aufnahmeleistung
- `B5 1A / 05 FF 32 1C`: Heizkreis-Solltemperatur
- `B5 1A / 05 00 32 1F`: Vorlauf-Solltemperatur
- `B5 1A / 05 00 32 20`: Vorlauf-Isttemperatur
- `B5 1A / 05 FF 32 21`: Energieintegral
- `B5 1A / 05 00 32 26`: Luftansaugtemperatur
- `B5 1A / 05 FF 32 27`: Quellentemperatur Ausgang
- `B5 1A / 05 FF 32 3D`: Anlagendruck
- `B5 1A / 05 FF 32 3E`: Quelldruck

Die Wärmeleistung wird lokal als Umweltleistung plus Aufnahmeleistung
berechnet. Das Modul sendet keine Test-, Service- oder Stellbefehle.

Die Heizkurve wird in Version 1.4 nur gelesen. Eine spätere Schreibfunktion
soll ausschließlich über eine explizite Whitelist für die Heizkurve erfolgen.

## Archiv

Alle vom Modul angelegten Statusvariablen werden automatisch im vorhandenen
IP-Symcon Archive Control aufgezeichnet und für die Visualisierung aktiviert.
Die Archivierung erfolgt ausschließlich lokal in IP-Symcon und erzeugt keinen
eBUS-Verkehr.

Die passiven Diagnosewerte für B5-24/B5-1A werden absichtlich nicht archiviert,
da sie bei jedem Telegramm aktualisiert werden und sonst unnötig viele
Archiveinträge erzeugen würden. Das Modul zeigt zusätzlich das zuletzt
beobachtete B5-1A-Telegramm als Hex-Text an, sammelt bis zu 32 verschiedene
B5-1A-Requesttypen und trennt den beobachteten aroTHERM/VWZ-Regelkreis in die
Untertelegramme `32` bis `36`. Für jeden dieser Typen wird Request und komplette
letzte Antwort gespeichert. Auch diese Diagnose ist rein passiv und sendet
keine Abfragen auf den eBUS.

Zusätzlich sammelt das Modul vorhandene B5-14-Telegramme. Dabei werden die
gesehenen IDs, die jeweilige Häufigkeit sowie Request und letzte vollständige
Antwort protokolliert. Es wird kein Testmodus aktiviert und kein B5-14-Request
vom Modul erzeugt.

Das Modul enthält außerdem einen passiven Änderungsrekorder für die
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

## Version 1.4: erweiterte HMU-Telemetrie

- Durchfluss des Gebäudekreises aus dem in dieser Anlage bestätigten passiven
  `B5 12 06 13`-Broadcast
- Kompressorauslastung aus dem bestätigten passiven `B5 11 01 07`-Broadcast
- optionale aktive Nur-Lese-Abfrage für die oben genannten HMU-Werte
- passive elektrische Aufnahmeleistung aus vorhandenem `B5 09` RunData
- berechnete Wärmeleistung = Umweltleistung + elektrische Aufnahmeleistung

Die HMU-Leseabfrage ist nach der Installation zunächst deaktiviert. Sie wird
in der Instanzkonfiguration über **HMU-Telemetrie aktiv abfragen
(ausschließlich lesen)** eingeschaltet. Das kleinste Intervall beträgt 30
Sekunden je Register. Für den ersten Funktionstest sind 30 Sekunden sinnvoll;
ein kompletter Durchlauf über alle zehn Register dauert dann etwa fünf Minuten.

Version 1.4 startet die Nur-Lese-Abfrage direkt auf der bereits aktiven
Enhanced-Verbindung. Damit ist sie nicht von einer erneuten INIT-Antwort des
ECO305 abhängig. Für diese Anlage wird die von der offiziellen HMU-Definition
ausgewiesene Live-Monitor-Lesekennung `05 00` verwendet. Die
eBUS-Prüfsummenbildung entspricht `Tabelle[alter CRC] XOR neues Byte`; damit
bestätigt die HMU die Leseanfrage statt sie mit `FF` abzulehnen.

Nicht bestätigte alte Doppelanzeigen werden ausgeblendet, bleiben beim Update
aber zur Kompatibilität erhalten. Die Heizkurve bleibt in Version 1.4
ausschließlich lesbar.
