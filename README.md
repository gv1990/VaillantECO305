# Vaillant ECO305 für IP-Symcon 9

Version 0.1 ist ein **rein passiver** Decoder für Vaillant-eBUS-Telegramme,
die über einen ESERA ECO305 im Enhanced Mode per TCP an IP-Symcon gelangen.

## Sicherheitsgrenze

- kein `EnableTest`
- keine Pumpenbefehle
- keine Ventilbefehle
- keine Kompressorbefehle
- keine Sicherheits-/Servicebefehle
- keine generische Raw-Send-Funktion

Version 0.1 enthält absichtlich **keinen** Aufruf von `SendDataToParent()`.
Kompressordaten werden nur ausgewertet, wenn sie bereits auf dem Bus vorhanden
sind.

Die Heizkurve wird in Version 0.1 nur gelesen. Eine spätere Schreibfunktion
soll ausschließlich über eine explizite Whitelist für die Heizkurve erfolgen.

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

