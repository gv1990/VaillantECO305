<?php

declare(strict_types=1);

/**
 * Vaillant ECO305 eBUS decoder for IP-Symcon 9.
 *
 * SAFETY DESIGN:
 * - Passive decoding remains enabled for all existing values.
 * - Build 25 centrally blocks every active eBUS transmission.
 * - No EnableTest messages.
 * - No compressor, pump, valve, service or safety commands.
 * - No caller-controlled raw messages and no configuration action buttons.
 * - All module status variables are logged locally by IP-Symcon Archive Control.
 *
 * ECO305 mode: Enhanced, TCP server.
 */
class VaillantECO305 extends IPSModuleStrict
{
    private const ACTIVE_TRAFFIC_ALLOWED = false;
    private const PARENT_DATA_ID = '{79827379-F36E-4ADA-8A95-5F8D1DC92FA9}';
    private const ENH_RES_RESETTED = 0x00;
    private const ENH_RES_RECEIVED = 0x01;
    private const ENH_RES_STARTED = 0x02;
    private const ENH_RES_FAILED = 0x0A;
    private const ENH_RES_ERROR_EBUS = 0x0B;
    private const ENH_RES_ERROR_HOST = 0x0C;
    private const EBUS_ESC = 0xA9;
    private const EBUS_SYN = 0xAA;
    private const EBUS_ACK = 0x00;
    private const EBUS_NAK = 0xFF;
    private const PROBE_MASTER = 0xFF;
    private const CONTROLLER_ADDRESS = 0x15;

    public function Create(): void
    {
        parent::Create();

        $this->RegisterPropertyBoolean('EnableActivePowerPolling', false);
        $this->RegisterPropertyInteger('PowerPollIntervalSeconds', 60);
        $this->RegisterTimer('PowerPoll', 0, 'VECO_PollPower($_IPS["TARGET"]);');

        // B5 24 - sensoCOMFORT / system values
        $this->RegisterVariableFloat('OutsideTemperature', 'Außentemperatur', '~Temperature', 10);
        $this->RegisterVariableFloat('WaterPressure', 'Wasserdruck [bar]', '', 20);
        $this->RegisterVariableFloat('SystemFlowTemperature', 'System Vorlauf', '~Temperature', 30);
        $this->RegisterVariableFloat('EnergyHeating', 'Energie Heizung [kWh]', '', 40);
        $this->RegisterVariableFloat('EnergyHotWater', 'Energie Warmwasser [kWh]', '', 50);
        $this->RegisterVariableFloat('HotWaterTarget', 'Warmwasser Soll', '~Temperature', 60);
        $this->RegisterVariableFloat('HotWaterActual', 'Warmwasser Ist', '~Temperature', 70);
        $this->RegisterVariableFloat('HotWaterFlow', 'Warmwasser Vorlauf', '~Temperature', 80);
        $this->RegisterVariableFloat('HeatingCircuit1TargetFlow', 'HK1 Vorlauf Soll', '~Temperature', 90);
        $this->RegisterVariableFloat('HeatingCircuit1Flow', 'HK1 Vorlauf Ist', '~Temperature', 100);
        $this->RegisterVariableFloat('HeatingCurve1', 'Heizkurve HK1', '', 110);

        // B5 1A - HMU normal live monitor, passive only
        $this->RegisterVariableFloat('HMUTargetHeatingCircuit', 'HMU Heizkreis Soll', '~Temperature', 200);
        $this->RegisterVariableFloat('HMUTargetFlow', 'HMU Vorlauf Soll', '~Temperature', 210);
        $this->RegisterVariableFloat('HMUFlowTemperature', 'HMU Vorlauf Ist', '~Temperature', 220);
        $this->RegisterVariableFloat('HMUEnergyIntegral', 'HMU Energieintegral', '', 230);
        $this->RegisterVariableFloat('HMUSourceInputTemperature', 'HMU Quellentemperatur Eingang', '~Temperature', 240);
        $this->RegisterVariableFloat('HMUCurrentEnvironmentalPower', 'HMU aktuelle Umweltleistung [kW]', '', 245);
        $this->RegisterVariableFloat('HMUCurrentYieldPower', 'HMU aktuelle Wärmeleistung [kW]', '', 250);
        $this->RegisterVariableFloat('HMUCurrentConsumedPower', 'HMU aktuelle Aufnahmeleistung [kW]', '', 260);
        $this->RegisterVariableFloat('HMUCompressorUtilization', 'Kompressor Auslastung [%] (nur lesen)', '', 270);
        $this->RegisterVariableFloat('HMUAirIntakeTemperature', 'HMU Luftansaugtemperatur', '~Temperature', 280);
        $this->RegisterVariableFloat('HMUSourceOutputTemperature', 'HMU Quellentemperatur Ausgang', '~Temperature', 285);
        $this->RegisterVariableFloat('HMUBuildingCircuitFlow', 'Durchfluss Heizkreis [l/h]', '', 290);
        $this->RegisterVariableFloat('HMUFlowPressure', 'HMU Anlagendruck [bar]', '', 300);
        $this->RegisterVariableFloat('HMUSourcePressure', 'HMU Quelldruck [bar]', '', 310);

        // Passive protocol diagnostics. Deliberately not archived.
        $this->RegisterVariableInteger('DiagB524Count', 'Diagnose: B5-24 Telegramme gesehen', '', 900);
        $this->RegisterVariableString('DiagLastB524Hex', 'Diagnose: Letztes B5-24 Telegramm', '', 902);
        $this->RegisterVariableString('DiagB524Types', 'Diagnose: B5-24 IDs und Antworten', '', 904);
        $this->RegisterVariableInteger('DiagB524ChangeCount', 'Diagnose: B5-24 Nutzdaten-Änderungen', '', 906);
        $this->RegisterVariableString('DiagB524Changes', 'Diagnose: B5-24 geänderte Nutzdaten', '', 908);
        $this->RegisterAttributeString('DiagB524TypesJSON', '{}');
        $this->RegisterAttributeString('DiagB524ChangesJSON', '{}');
        $this->RegisterVariableInteger('DiagB51ACount', 'Diagnose: B5-1A Telegramme gesehen', '', 910);
        $this->RegisterVariableString('DiagLastB51AHex', 'Diagnose: Letztes B5-1A Telegramm', '', 920);
        $this->RegisterVariableString('DiagB51ATypes', 'Diagnose: B5-1A Requesttypen', '', 930);
        $this->RegisterVariableString('DiagB51A32', 'Diagnose: B5-1A 32 letzte Antwort', '', 940);
        $this->RegisterVariableString('DiagB51A33', 'Diagnose: B5-1A 33 letzte Antwort', '', 950);
        $this->RegisterVariableString('DiagB51A34', 'Diagnose: B5-1A 34 letzte Antwort', '', 960);
        $this->RegisterVariableString('DiagB51A35', 'Diagnose: B5-1A 35 letzte Antwort', '', 970);
        $this->RegisterVariableString('DiagB51A36', 'Diagnose: B5-1A 36 letzte Antwort', '', 980);
        $this->RegisterAttributeString('DiagB51ATypesJSON', '{}');

        // B5 14 passive sensor/service traffic diagnostics. No requests are sent.
        $this->RegisterVariableInteger('DiagB514Count', 'Diagnose: B5-14 Telegramme gesehen', '', 990);
        $this->RegisterVariableString('DiagLastB514Hex', 'Diagnose: Letztes B5-14 Telegramm', '', 1000);
        $this->RegisterVariableString('DiagB514Types', 'Diagnose: B5-14 IDs und Antworten', '', 1010);
        $this->RegisterAttributeString('DiagB514TypesJSON', '{}');

        // Retain transient payload changes in B5-1A 32..36. Counter byte 0 is ignored.
        $this->RegisterVariableInteger('DiagB51AChangeCount', 'Diagnose: B5-1A Nutzdaten-Änderungen', '', 1020);
        $this->RegisterVariableString('DiagB51AChanges', 'Diagnose: B5-1A geänderte Nutzbytes', '', 1030);
        $this->RegisterAttributeString('DiagB51APreviousJSON', '{}');
        $this->RegisterAttributeString('DiagB51AChangesJSON', '{}');

        $this->RegisterVariableString('PowerReadStatus', 'HMU-Leseabfrage Status', '', 1040);
        $this->RegisterVariableString('PowerReadLastResponse', 'HMU-Leseabfrage letzte Antwort', '', 1050);
        $this->RegisterVariableString('PowerReadLastRequest', 'Leseabfrage gesendete Anforderung', '', 1060);
        $this->RegisterVariableString('PowerReadTrace', 'Leseabfrage Diagnoseablauf', '', 1070);

        // Passive safety diagnostic used to identify already occupied eBUS
        // source addresses before any further active request is considered.
        $this->RegisterVariableString('DiagObservedSources', 'Diagnose: Passiv beobachtete eBUS-Absender', '', 1080);
        $this->RegisterAttributeString('DiagObservedSourcesJSON', '{}');
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();
        // Build 25 is strictly passive. Timers, manual actions and the final
        // socket send path are all locked against active eBUS traffic.
        $this->SetTimerInterval('PowerPoll', 0);
        $this->SetSummary('ECO305 Enhanced - ausschließlich passiv - V1.4');

        $this->SetBuffer('PowerReadState', '');
        $this->SetBuffer('EnhancedRxPartial', '');
        $this->SetBuffer('PassiveFrame', '');
        $this->SetBuffer('PassiveEscape', '0');
        $this->SetBuffer('PassiveSynchronized', '0');
        // Keep the strict address and CRC validation introduced with build 21.
        // Start a fresh observation window whenever this build is applied.
        $this->WriteAttributeString('DiagObservedSourcesJSON', '{}');
        $this->SetValue('DiagObservedSources', 'Warte auf vollständig empfangene Telegramme mit gültiger CRC');
        // The ECO305 connection is already delivering enhanced telegrams.
        // Some ECO305 firmware does not answer a repeated INIT on an existing
        // TCP session, therefore active reads start directly on this stream.
        $this->SetBuffer('EnhancedInitialized', '1');
        // These legacy placeholders have no confirmed register on this plant.
        // Keep the objects for upgrade compatibility, but do not present a
        // permanent "Nie" as though it were a failed measurement.
        foreach (['SystemFlowTemperature', 'HotWaterFlow', 'HeatingCircuit1Flow', 'HMUSourceInputTemperature'] as $ident) {
            $objectID = @IPS_GetObjectIDByIdent($ident, $this->InstanceID);
            if ($objectID !== false) {
                IPS_SetHidden($objectID, true);
            }
        }

        $this->SetValue('PowerReadStatus', 'Build 25 passiv – sämtliche aktiven eBUS-Abfragen gesperrt');
        $this->EnableArchiveLogging();
    }

    public function GetConfigurationForm(): string
    {
        return json_encode([
            'elements' => [
                [
                    'type'    => 'Label',
                    'caption' => 'Build 25 arbeitet ausschließlich passiv. Es gibt keine Geräteabfrage, keine Arbitrierung, keine Wiederholung und kein Schreibtelegramm.'
                ],
                [
                    'type'    => 'Label',
                    'caption' => 'Unter den Statusvariablen zeigt „Diagnose: Passiv beobachtete eBUS-Absender“ alle vollständig empfangenen Absender mit Anzahl und Zeitstempel.'
                ]
            ],
            'actions' => []
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * Enable IP-Symcon's local archive and graph for every status variable
     * directly below this module instance. This does not communicate with eBUS.
     */
    private function EnableArchiveLogging(): void
    {
        $archives = IPS_GetInstanceListByModuleID('{43192F0B-135B-4CE7-A0A7-1475603F3060}');
        if ($archives === []) {
            $this->SendDebug('Archive', 'Archive Control nicht gefunden', 0);
            return;
        }

        $archiveID = $archives[0];
        foreach (IPS_GetChildrenIDs($this->InstanceID) as $objectID) {
            $object = IPS_GetObject($objectID);
            if ($object['ObjectType'] !== 2) {
                continue;
            }

            // High-frequency counters are only for protocol diagnosis and
            // must not fill Archive Control with one entry per telegram.
            if (strncmp($object['ObjectIdent'], 'Diag', 4) === 0 ||
                strncmp($object['ObjectIdent'], 'PowerRead', 9) === 0 ||
                strncmp($object['ObjectIdent'], 'HeatPumpLoadProfile', 19) === 0) {
                continue;
            }

            AC_SetLoggingStatus($archiveID, $objectID, true);
            AC_SetGraphStatus($archiveID, $objectID, true);
        }
    }

    /**
     * IP-Symcon Strict receives binary I/O buffers HEX encoded.
     */
    public function ReceiveData(string $JSONString): string
    {
        $packet = json_decode($JSONString, true);
        if (!is_array($packet) || !isset($packet['Buffer']) || !is_string($packet['Buffer'])) {
            return '';
        }

        $incoming = hex2bin($packet['Buffer']);
        if ($incoming === false || $incoming === '') {
            return '';
        }

        $partialHex = $this->GetBuffer('EnhancedRxPartial');
        $partial = $partialHex !== '' ? hex2bin($partialHex) : '';
        if ($partial === false) {
            $partial = '';
        }

        $data = $partial . $incoming;
        $length = strlen($data);
        $position = 0;

        while ($position < $length) {
            $first = ord($data[$position]);

            // Plain bytes are legal in the enhanced stream and mean a
            // normally received eBUS symbol.
            if (($first & 0x80) === 0) {
                $position++;
                $this->HandleEnhancedEvent(self::ENH_RES_RECEIVED, $first);
                continue;
            }

            $kind = $first & 0xC0;
            if ($kind === 0x80) {
                // Orphaned second byte: discard it and regain framing.
                $position++;
                continue;
            }

            if (($position + 1) >= $length) {
                break;
            }

            $second = ord($data[$position + 1]);
            if (($second & 0xC0) !== 0x80) {
                $position++;
                continue;
            }

            $command = ($first >> 2) & 0x0F;
            $value = (($first & 0x03) << 6) | ($second & 0x3F);
            $position += 2;
            $this->HandleEnhancedEvent($command, $value);
        }

        $rest = substr($data, $position);
        $this->SetBuffer('EnhancedRxPartial', bin2hex($rest));

        return '';
    }

    private function HandleEnhancedEvent(int $command, int $value): void
    {
        if ($command === self::ENH_RES_RESETTED) {
            $this->SetBuffer('PowerReadState', '');
            $this->SetBuffer('EnhancedInitialized', '1');
            $this->SetValue('PowerReadStatus', 'ECO305 initialisiert – Build 25 bleibt vollständig passiv');
            return;
        }

        if ($command === self::ENH_RES_STARTED ||
            $command === self::ENH_RES_FAILED ||
            $command === self::ENH_RES_ERROR_EBUS ||
            $command === self::ENH_RES_ERROR_HOST) {
            $this->HandlePowerProtocolEvent($command, $value);
            return;
        }

        if ($command !== self::ENH_RES_RECEIVED) {
            return;
        }

        // The active request consumes the same raw symbols, but passive
        // decoding continues in parallel so no existing telemetry is lost.
        $this->HandlePowerProtocolEvent($command, $value);
        $this->AppendPassiveSymbol($value);
    }

    private function AppendPassiveSymbol(int $value): void
    {
        if ($value === self::EBUS_SYN) {
            $frameHex = $this->GetBuffer('PassiveFrame');
            if ($this->GetBuffer('PassiveSynchronized') === '1' && $frameHex !== '') {
                $frame = hex2bin($frameHex);
                if ($frame !== false && $frame !== '') {
                    $this->ProcessTelegram(array_values(unpack('C*', $frame)));
                }
            }
            $this->SetBuffer('PassiveFrame', '');
            $this->SetBuffer('PassiveEscape', '0');
            $this->SetBuffer('PassiveSynchronized', '1');
            return;
        }

        // Ignore a partial predecessor after startup/reload. The first SYN
        // establishes a clean eBUS telegram boundary.
        if ($this->GetBuffer('PassiveSynchronized') !== '1') {
            return;
        }

        if ($this->GetBuffer('PassiveEscape') === '1') {
            if ($value === 0x00) {
                $value = self::EBUS_ESC;
            } elseif ($value === 0x01) {
                $value = self::EBUS_SYN;
            } else {
                $this->SetBuffer('PassiveFrame', '');
                $this->SetBuffer('PassiveEscape', '0');
                return;
            }
            $this->SetBuffer('PassiveEscape', '0');
        } elseif ($value === self::EBUS_ESC) {
            $this->SetBuffer('PassiveEscape', '1');
            return;
        }

        $frameHex = $this->GetBuffer('PassiveFrame') . sprintf('%02x', $value);
        if (strlen($frameHex) > 16384) {
            $frameHex = substr($frameHex, -16384);
        }
        $this->SetBuffer('PassiveFrame', $frameHex);
    }

    /** Build 25 safety lock: active HMU requests are unavailable. */
    public function PollPower(): void
    {
        $this->SetValue('PowerReadStatus', 'Sicherheitssperre aktiv – aktive Abfrage nicht gesendet');
    }

    /** Build 25 safety lock: active heating-curve reads are unavailable. */
    public function PollHeatingCurve(): void
    {
        $this->SetValue('PowerReadStatus', 'Build 25 passiv – Heizkurvenabfrage nicht gesendet');
    }

    /**
     * Perform one arbitration-only test with FF and release the bus
     * immediately. No destination, command, payload, or device request is
     * transmitted by this operation.
     */
    public function ProbeMasterAddress(): void
    {
        $this->SetValue('PowerReadStatus', 'Build 25 passiv – Arbitrierungstest nicht gesendet');
    }

    private function StartHeatingCurveRead(): void
    {
        $current = $this->ReadPowerState();
        if (($current['active'] ?? false) === true) {
            $this->SetValue('PowerReadStatus', 'Anderer Protokollvorgang läuft – Heizkurve nicht erneut abgefragt');
            return;
        }

        $definition = $this->FindTelemetryDefinition('heating_curve');
        if ($definition === null ||
            ($definition['protocol'] ?? '') !== 'b524' ||
            ($definition['request'] ?? null) !== [0x02, 0x00, 0x02, 0x00, 0x0F, 0x00]) {
            $this->SetValue('PowerReadStatus', 'Interne Sicherheitsprüfung fehlgeschlagen – nichts gesendet');
            return;
        }

        // Fixed whitelist: FF -> controller 15, B5 24 read key
        // 02 00 02 00 0F 00. No caller-controlled byte is accepted here.
        $master = array_merge([
            self::PROBE_MASTER,
            self::CONTROLLER_ADDRESS,
            0xB5,
            0x24,
            0x06
        ], $definition['request']);
        $masterWire = $this->EscapeEbusBytes($master);
        $crc = $this->CalculateCrc($masterWire);
        $txWire = array_merge(array_slice($masterWire, 1), $this->EscapeEbusBytes([$crc]));

        $state = [
            'active'           => true,
            'mode'             => 'heating_curve_read',
            'started'          => time(),
            'stage'            => 'wait_bus_syn',
            'key'              => $definition['key'],
            'request'          => $master,
            'txWire'           => $txWire,
            'txPos'            => 0,
            'lastSent'         => -1,
            'responseLogical'  => [],
            'responseExpected' => 0,
            'responseCrc'      => 0,
            'responseEscape'   => false,
            'responseCrcBytes' => [],
            'responseValid'    => false
        ];
        $this->WritePowerState($state);
        $this->SetValue('PowerReadLastRequest', $this->BytesToHex(array_merge($master, [$crc])));
        $this->SetValue('PowerReadTrace', '');
        $this->TracePowerRead(sprintf(
            'VORGEMERKT %s | wartet passiv auf SYN AA | Protokoll %s | Anforderung %s | Sendedaten %s',
            (string) $definition['key'],
            'b524',
            $this->BytesToHex(array_merge($master, [$crc])),
            $this->BytesToHex($txWire)
        ));
        $this->SetValue('PowerReadStatus', 'Heizkurven-Leseabfrage vorgemerkt – wartet passiv auf nächstes SYN AA');
    }

    private function StartArmedHeatingCurveAtSyn(): void
    {
        $state = $this->ReadPowerState();
        if (($state['active'] ?? false) !== true ||
            ($state['mode'] ?? '') !== 'heating_curve_read' ||
            ($state['stage'] ?? '') !== 'wait_bus_syn') {
            return;
        }

        $state['stage'] = 'wait_start';
        $state['started'] = time();
        $this->WritePowerState($state);
        $this->SetValue('PowerReadStatus', 'SYN-AA-Busgrenze erkannt – Arbitrierung FF gestartet');
        $this->TracePowerRead('BUSGRENZE ERKANNT | SYN AA | START Arbitrierung Master FF');
        $this->SendEnhanced(0x02, self::PROBE_MASTER);
    }

    private function HandlePowerProtocolEvent(int $command, int $value): void
    {
        $state = $this->ReadPowerState();
        if (($state['active'] ?? false) !== true) {
            return;
        }

        // No command has been sent while merely waiting for a passive SYN.
        // Any adapter error seen in this stage belongs to unrelated traffic
        // and must neither abort nor trigger the armed one-shot read.
        if (($state['stage'] ?? '') === 'wait_bus_syn') {
            return;
        }

        if ($command === self::ENH_RES_FAILED) {
            $this->TracePowerReadState('ECO305 BUSZUGRIFF BELEGT', $state, $command, $value);
            if (($state['mode'] ?? '') === 'address_probe') {
                $this->SetValue('PowerReadStatus', 'Arbitrierung FF nicht gewonnen – keine Geräteabfrage gesendet');
                $this->SetBuffer('PowerReadState', '');
                return;
            }
            $this->SetValue('PowerReadStatus', 'Buszugriff belegt – Heizkurve nicht abgefragt; keine Wiederholung');
            $this->SetBuffer('PowerReadState', '');
            return;
        }
        if ($command === self::ENH_RES_ERROR_EBUS || $command === self::ENH_RES_ERROR_HOST) {
            $errorName = $command === self::ENH_RES_ERROR_HOST ? 'ERROR_HOST' : 'ERROR_EBUS';
            $this->TracePowerReadState('ECO305 ' . $errorName, $state, $command, $value);
            if (($state['mode'] ?? '') === 'address_probe') {
                $this->SetValue('PowerReadStatus', sprintf(
                    'Arbitrierungstest FF abgebrochen | %s %02X | keine Geräteabfrage gesendet',
                    $errorName,
                    $value
                ));
                $this->SetBuffer('PowerReadState', '');
                return;
            }
            $this->SetValue('PowerReadStatus', sprintf(
                'Heizkurven-Leseabfrage abgebrochen | %s %02X | Stufe %s | keine Wiederholung',
                $errorName,
                $value,
                (string) ($state['stage'] ?? '-')
            ));
            $this->SetBuffer('PowerReadState', '');
            return;
        }

        $stage = (string) ($state['stage'] ?? '');
        if ($stage === 'wait_start') {
            $isAddressProbe = ($state['mode'] ?? '') === 'address_probe';
            $expectedMaster = self::PROBE_MASTER;
            if ($command !== self::ENH_RES_STARTED || $value !== $expectedMaster) {
                return;
            }
            $this->TracePowerRead('ARBITRIERUNG ERFOLGREICH | Master ' . sprintf('%02X', $value));
            if ($isAddressProbe) {
                $state['stage'] = 'send_probe_syn';
                $state['lastSent'] = self::EBUS_SYN;
                $this->WritePowerState($state);
                $this->SendEnhanced(0x01, self::EBUS_SYN);
                return;
            }
            $state['stage'] = 'send_master';
            $this->SendNextPowerByte($state);
            return;
        }

        if ($command !== self::ENH_RES_RECEIVED) {
            return;
        }

        if ($stage === 'send_master') {
            if ($value !== (int) ($state['lastSent'] ?? -1)) {
                $this->AbortPowerRead('Unerwartetes Echo beim Senden');
                return;
            }
            $state['txPos'] = (int) $state['txPos'] + 1;
            if ($state['txPos'] < count($state['txWire'])) {
                $this->SendNextPowerByte($state);
                return;
            }
            $state['stage'] = 'wait_command_ack';
            $this->WritePowerState($state);
            return;
        }

        if ($stage === 'send_probe_syn') {
            if ($value !== self::EBUS_SYN) {
                $this->TracePowerReadState('UNERWARTETES ECHO BEIM FREIGEBEN', $state, $command, $value);
                $this->SetValue('PowerReadStatus', 'Arbitrierung gewonnen, Busfreigabe nicht bestätigt – keine Geräteabfrage gesendet');
                $this->SetBuffer('PowerReadState', '');
                return;
            }
            $this->TracePowerRead('BUS SOFORT FREIGEGEBEN | SYN AA bestätigt | keine Geräteabfrage gesendet');
            $this->SetValue('PowerReadStatus', 'Arbitrierung FF erfolgreich; Bus sofort freigegeben; keine Geräteabfrage gesendet');
            $this->SetBuffer('PowerReadState', '');
            return;
        }

        if ($stage === 'wait_command_ack') {
            if ($value !== self::EBUS_ACK) {
                $this->TracePowerReadState('ZIEL NICHT BESTÄTIGT', $state, $command, $value);
                $this->AbortPowerRead(
                    'Regler hat die Heizkurven-Leseabfrage nicht bestätigt (Antwort ' . sprintf('%02X', $value) . ')'
                );
                return;
            }
            $this->TracePowerRead('ZIEL BESTÄTIGT | ACK 00 | Antwort wird gelesen');
            $state['stage'] = 'receive_response';
            $this->WritePowerState($state);
            return;
        }

        if ($stage === 'receive_response') {
            $this->ConsumePowerResponseByte($state, $value);
            return;
        }

        if ($stage === 'send_response_ack') {
            if ($value !== (int) ($state['lastSent'] ?? -1)) {
                $this->AbortPowerRead('Unerwartetes Echo der Antwortbestätigung');
                return;
            }
            $state['stage'] = 'send_syn';
            $state['lastSent'] = self::EBUS_SYN;
            $this->WritePowerState($state);
            $this->SendEnhanced(0x01, self::EBUS_SYN);
            return;
        }

        if ($stage === 'send_syn' && $value === self::EBUS_SYN) {
            $this->TracePowerRead('TRANSAKTION BEENDET | SYN AA');
            $this->CompletePowerRead($state);
        }
    }

    /** @param array<string, mixed> $state */
    private function SendNextPowerByte(array $state): void
    {
        $position = (int) $state['txPos'];
        $wire = $state['txWire'];
        if (!is_array($wire) || !isset($wire[$position])) {
            $this->AbortPowerRead('Interner Sendefehler');
            return;
        }

        $state['lastSent'] = (int) $wire[$position];
        $this->WritePowerState($state);
        $this->SendEnhanced(0x01, (int) $wire[$position]);
    }

    /** @param array<string, mixed> $state */
    private function ConsumePowerResponseByte(array $state, int $raw): void
    {
        $logical = is_array($state['responseLogical'] ?? null) ? $state['responseLogical'] : [];
        $expected = (int) ($state['responseExpected'] ?? 0);

        // Once length + payload are complete, the following logical byte is
        // the response CRC and must not be included in its own calculation.
        if ($expected > 0 && count($logical) >= $expected) {
            $crcBytes = is_array($state['responseCrcBytes'] ?? null) ? $state['responseCrcBytes'] : [];
            $crcBytes[] = $raw;
            $state['responseCrcBytes'] = $crcBytes;
            $decodedCrc = $this->DecodeSingleEscapedByte($crcBytes);
            if ($decodedCrc === null) {
                $this->WritePowerState($state);
                return;
            }

            $valid = $decodedCrc === (int) $state['responseCrc'];
            $this->TracePowerRead(sprintf(
                'ANTWORT VOLLSTÄNDIG | Daten %s | CRC empfangen %02X | CRC berechnet %02X | %s',
                $this->BytesToHex($logical),
                $decodedCrc,
                (int) $state['responseCrc'],
                $valid ? 'gültig' : 'ungültig'
            ));
            $state['responseValid'] = $valid;
            $state['stage'] = 'send_response_ack';
            $state['lastSent'] = $valid ? self::EBUS_ACK : self::EBUS_NAK;
            $this->WritePowerState($state);
            $this->SendEnhanced(0x01, (int) $state['lastSent']);
            return;
        }

        $state['responseCrc'] = $this->UpdateCrc((int) $state['responseCrc'], $raw);
        $escape = (bool) ($state['responseEscape'] ?? false);
        if ($escape) {
            if ($raw === 0x00) {
                $logical[] = self::EBUS_ESC;
            } elseif ($raw === 0x01) {
                $logical[] = self::EBUS_SYN;
            } else {
                $this->AbortPowerRead('Ungültige Escape-Sequenz in Reglerantwort');
                return;
            }
            $state['responseEscape'] = false;
        } elseif ($raw === self::EBUS_ESC) {
            $state['responseEscape'] = true;
            $this->WritePowerState($state);
            return;
        } elseif ($raw === self::EBUS_SYN) {
            $this->AbortPowerRead('Reglerantwort vorzeitig beendet');
            return;
        } else {
            $logical[] = $raw;
        }

        if (count($logical) === 1) {
            $payloadLength = (int) $logical[0];
            if ($payloadLength < 4 || $payloadLength > 32) {
                $this->AbortPowerRead('Unplausible Reglerantwortlänge');
                return;
            }
            $state['responseExpected'] = 1 + $payloadLength;
        }
        $state['responseLogical'] = $logical;
        $this->WritePowerState($state);
    }

    /** @param array<string, mixed> $state */
    private function CompletePowerRead(array $state): void
    {
        $valid = (bool) ($state['responseValid'] ?? false);
        $logical = is_array($state['responseLogical'] ?? null) ? $state['responseLogical'] : [];
        $key = (string) ($state['key'] ?? '');

        $definition = $this->FindTelemetryDefinition($key);
        if ($valid && $definition !== null && $this->DecodeActiveTelemetryResponse($definition, $logical)) {
            $this->SetValue('PowerReadLastResponse', strtoupper(implode(' ', array_map(
                static fn (int $byte): string => sprintf('%02x', $byte),
                $logical
            ))));
            $this->SetValue('PowerReadStatus', $definition['label'] . ' erfolgreich gelesen');
        } elseif (!$valid) {
            $this->SetValue('PowerReadStatus', 'Reglerantwort mit ungültiger Prüfsumme');
        }

        $this->SetBuffer('PowerReadState', '');
    }

    /** @param array<int, int> $logical */
    private function DecodeActiveTelemetryResponse(array $definition, array $logical): bool
    {
        $payloadOffset = (int) ($definition['payloadOffset'] ?? 4);
        if (count($logical) <= $payloadOffset) {
            $this->SetValue('PowerReadStatus', 'Reglerantwort enthält keinen Messwert');
            return false;
        }

        // Byte 0 is the slave length. The register definition fixes how many
        // response/header bytes precede the value.
        $payload = array_slice($logical, $payloadOffset);
        $decoder = (string) $definition['decoder'];
        $minimumBytes = $decoder === 'exp' ? 4 : 2;
        if (count($payload) < $minimumBytes) {
            $this->SetValue('PowerReadStatus', 'Reglerantwort ist zu kurz');
            return false;
        }

        if ($decoder === 'd2c') {
            $raw = $this->Int16LE($payload);
            $value = $raw === null ? null : $raw / 16.0;
        } elseif ($decoder === 'sin') {
            $raw = $this->Int16LE($payload);
            $value = $raw === null ? null : (float) $raw;
        } elseif ($decoder === 'uin10') {
            $raw = $this->UInt16LE($payload);
            $value = $raw === null ? null : $raw / 10.0;
        } elseif ($decoder === 'pressure4') {
            $raw = $this->Int16LE($payload);
            $value = $raw === null ? null : $raw / 4.0;
        } elseif ($decoder === 'exp') {
            $value = $this->FloatLE($payload);
        } else {
            return false;
        }

        $minimum = (float) $definition['minimum'];
        $maximum = (float) $definition['maximum'];
        if ($value === null || $value < $minimum || $value > $maximum) {
            $this->SetValue('PowerReadStatus', $definition['label'] . ': Messwert unplausibel');
            return false;
        }

        $this->SetValue((string) $definition['ident'], $value);
        if (($definition['thermal'] ?? false) === true) {
            $this->UpdateThermalPower();
        }
        return true;
    }

    /** @return array<int, array<string, mixed>> */
    private function GetTelemetryDefinitions(): array
    {
        return [
            ['key' => 'environmental', 'label' => 'Umweltleistung', 'request' => [0x05, 0x00, 0x32, 0x23], 'ident' => 'HMUCurrentEnvironmentalPower', 'decoder' => 'uin10', 'minimum' => 0, 'maximum' => 30, 'thermal' => true],
            ['key' => 'consumed', 'label' => 'Aufnahmeleistung', 'request' => [0x05, 0x00, 0x32, 0x24], 'ident' => 'HMUCurrentConsumedPower', 'decoder' => 'uin10', 'minimum' => 0, 'maximum' => 30, 'thermal' => true],
            ['key' => 'target_hc', 'label' => 'HMU Heizkreis Soll', 'request' => [0x05, 0xFF, 0x32, 0x1C], 'ident' => 'HMUTargetHeatingCircuit', 'decoder' => 'd2c', 'minimum' => -60, 'maximum' => 120],
            ['key' => 'target_flow', 'label' => 'HMU Vorlauf Soll', 'request' => [0x05, 0x00, 0x32, 0x1F], 'ident' => 'HMUTargetFlow', 'decoder' => 'd2c', 'minimum' => -60, 'maximum' => 120],
            ['key' => 'flow_temp', 'label' => 'HMU Vorlauf Ist', 'request' => [0x05, 0x00, 0x32, 0x20], 'ident' => 'HMUFlowTemperature', 'decoder' => 'd2c', 'minimum' => -60, 'maximum' => 120],
            ['key' => 'energy_integral', 'label' => 'HMU Energieintegral', 'request' => [0x05, 0xFF, 0x32, 0x21], 'ident' => 'HMUEnergyIntegral', 'decoder' => 'sin', 'minimum' => -32768, 'maximum' => 32767],
            ['key' => 'air_intake', 'label' => 'HMU Luftansaugtemperatur', 'request' => [0x05, 0x00, 0x32, 0x26], 'ident' => 'HMUAirIntakeTemperature', 'decoder' => 'd2c', 'minimum' => -60, 'maximum' => 120],
            ['key' => 'source_output', 'label' => 'HMU Quellentemperatur Ausgang', 'request' => [0x05, 0xFF, 0x32, 0x27], 'ident' => 'HMUSourceOutputTemperature', 'decoder' => 'd2c', 'minimum' => -60, 'maximum' => 120],
            ['key' => 'flow_pressure', 'label' => 'HMU Anlagendruck', 'request' => [0x05, 0xFF, 0x32, 0x3D], 'ident' => 'HMUFlowPressure', 'decoder' => 'pressure4', 'minimum' => 0, 'maximum' => 100],
            ['key' => 'source_pressure', 'label' => 'HMU Quelldruck', 'request' => [0x05, 0xFF, 0x32, 0x3E], 'ident' => 'HMUSourcePressure', 'decoder' => 'pressure4', 'minimum' => 0, 'maximum' => 100],
            ['key' => 'heating_curve', 'label' => 'Heizkurve HK1', 'protocol' => 'b524', 'manualOnly' => true, 'request' => [0x02, 0x00, 0x02, 0x00, 0x0F, 0x00], 'payloadOffset' => 5, 'ident' => 'HeatingCurve1', 'decoder' => 'exp', 'minimum' => 0, 'maximum' => 5]
        ];
    }

    /** @return array<string, mixed>|null */
    private function FindTelemetryDefinition(string $key): ?array
    {
        foreach ($this->GetTelemetryDefinitions() as $definition) {
            if ($definition['key'] === $key) {
                return $definition;
            }
        }
        return null;
    }

    private function AbortPowerRead(string $message): void
    {
        $state = $this->ReadPowerState();
        $stage = (string) ($state['stage'] ?? '');
        $wasActive = ($state['active'] ?? false) === true;
        $this->SetValue('PowerReadStatus', $message);
        $this->SetBuffer('PowerReadState', '');

        if ($wasActive && $stage !== 'wait_start') {
            // End a transaction that was already won. SYN is the mandatory
            // eBUS synchronisation symbol, not a device command. If
            // arbitration never started, no second start attempt is made.
            $this->SendEnhanced(0x01, self::EBUS_SYN);
        }
    }

    private function TracePowerReadState(string $message, array $state, int $command, int $value): void
    {
        $this->TracePowerRead(sprintf(
            '%s | Kommando %02X | Wert %02X | Stufe %s | Sendeposition %d/%d | Letztes Byte %02X | Antwort %s | CRC-Bytes %s',
            $message,
            $command,
            $value,
            (string) ($state['stage'] ?? '-'),
            (int) ($state['txPos'] ?? 0),
            is_array($state['txWire'] ?? null) ? count($state['txWire']) : 0,
            ((int) ($state['lastSent'] ?? -1)) & 0xFF,
            is_array($state['responseLogical'] ?? null) ? $this->BytesToHex($state['responseLogical']) : '',
            is_array($state['responseCrcBytes'] ?? null) ? $this->BytesToHex($state['responseCrcBytes']) : ''
        ));
    }

    private function TracePowerRead(string $message): void
    {
        $current = trim((string) $this->GetValue('PowerReadTrace'));
        $lines = $current === '' ? [] : preg_split('/\R/', $current);
        if (!is_array($lines)) {
            $lines = [];
        }
        $lines[] = date('d.m.Y H:i:s') . ' | ' . $message;
        if (count($lines) > 40) {
            $lines = array_slice($lines, -40);
        }
        $this->SetValue('PowerReadTrace', implode("\n", $lines));
    }

    /** @return array<string, mixed> */
    private function ReadPowerState(): array
    {
        $json = $this->GetBuffer('PowerReadState');
        if ($json === '') {
            return [];
        }
        $state = json_decode($json, true);
        return is_array($state) ? $state : [];
    }

    /** @param array<string, mixed> $state */
    private function WritePowerState(array $state): void
    {
        $this->SetBuffer('PowerReadState', json_encode($state, JSON_THROW_ON_ERROR));
    }

    /** @param array<int, int> $bytes @return array<int, int> */
    private function EscapeEbusBytes(array $bytes): array
    {
        $wire = [];
        foreach ($bytes as $byte) {
            if ($byte === self::EBUS_ESC) {
                $wire[] = self::EBUS_ESC;
                $wire[] = 0x00;
            } elseif ($byte === self::EBUS_SYN) {
                $wire[] = self::EBUS_ESC;
                $wire[] = 0x01;
            } else {
                $wire[] = $byte;
            }
        }
        return $wire;
    }

    /** @param array<int, int> $wire */
    private function CalculateCrc(array $wire): int
    {
        $crc = 0;
        foreach ($wire as $byte) {
            $crc = $this->UpdateCrc($crc, $byte);
        }
        return $crc;
    }

    private function UpdateCrc(int $crc, int $value): int
    {
        // eBUS does not use the usual table[crc XOR value] order. Its
        // definition is table[crc] XOR value: first advance the current CRC
        // with polynomial 0x9B, then combine the next transmitted byte.
        for ($bit = 0; $bit < 8; $bit++) {
            $crc = ($crc & 0x80) !== 0
                ? (($crc << 1) ^ 0x9B) & 0xFF
                : ($crc << 1) & 0xFF;
        }
        return ($crc ^ $value) & 0xFF;
    }

    /** @param array<int, int> $bytes */
    private function DecodeSingleEscapedByte(array $bytes): ?int
    {
        if ($bytes === []) {
            return null;
        }
        if ($bytes[0] !== self::EBUS_ESC) {
            return $bytes[0];
        }
        if (!isset($bytes[1])) {
            return null;
        }
        if ($bytes[1] === 0x00) {
            return self::EBUS_ESC;
        }
        if ($bytes[1] === 0x01) {
            return self::EBUS_SYN;
        }
        return null;
    }

    private function SendEnhanced(int $command, int $value): void
    {
        if (!self::ACTIVE_TRAFFIC_ALLOWED) {
            $this->SetValue('PowerReadStatus', 'Build 25 passiv – zentrale Sendesperre aktiv');
            $this->SetBuffer('PowerReadState', '');
            return;
        }

        $first = 0xC0 | (($command & 0x0F) << 2) | (($value & 0xC0) >> 6);
        $second = 0x80 | ($value & 0x3F);
        $binary = chr($first) . chr($second);

        try {
            $this->SendDataToParent(json_encode([
                'DataID' => self::PARENT_DATA_ID,
                'Buffer' => bin2hex($binary)
            ], JSON_THROW_ON_ERROR));
        } catch (Throwable $error) {
            $this->SetValue('PowerReadStatus', 'Senden fehlgeschlagen: ' . $error->getMessage());
            $this->SetBuffer('PowerReadState', '');
        }
    }

    /** @param array<int, int> $telegram */
    private function ProcessTelegram(array $telegram): void
    {
        $this->UpdateObservedSourceDiagnostic($telegram);

        $count = count($telegram);
        for ($p = 0; $p <= $count - 3; $p++) {
            if ($telegram[$p] !== 0xB5) {
                continue;
            }

            if (($telegram[$p + 1] ?? -1) === 0x09) {
                $this->ProcessB509($telegram, $p);
            } elseif (($telegram[$p + 1] ?? -1) === 0x11) {
                $this->ProcessB511($telegram, $p);
            } elseif (($telegram[$p + 1] ?? -1) === 0x12) {
                $this->ProcessB512($telegram, $p);
            } elseif (($telegram[$p + 1] ?? -1) === 0x24) {
                $this->IncrementDiagnostic('DiagB524Count');
                $this->SetValue('DiagLastB524Hex', $this->BytesToHex($telegram));
                $this->UpdateB524TypeDiagnostic($telegram, $p);
                $this->ProcessB524($telegram, $p);
            } elseif (($telegram[$p + 1] ?? -1) === 0x14) {
                $this->IncrementDiagnostic('DiagB514Count');
                $this->SetValue('DiagLastB514Hex', $this->BytesToHex($telegram));
                $this->UpdateB514TypeDiagnostic($telegram, $p);
            } elseif (($telegram[$p + 1] ?? -1) === 0x1A) {
                $this->IncrementDiagnostic('DiagB51ACount');
                $this->SetValue('DiagLastB51AHex', $this->BytesToHex($telegram));
                $this->UpdateB51ATypeDiagnostic($telegram, $p);
                $this->UpdateB51AControlLoopDiagnostic($telegram, $p);
                $this->ProcessB51A($telegram, $p);
            }
        }
    }

    /**
     * Record only the source address of structurally complete passive master
     * telegrams. This routine never sends data to the eBUS.
     *
     * @param array<int, int> $telegram
     */
    private function UpdateObservedSourceDiagnostic(array $telegram): void
    {
        if (count($telegram) < 6 || !isset($telegram[0], $telegram[1], $telegram[4])) {
            return;
        }

        $sourceByte = (int) $telegram[0];
        $allowedMasterNibbles = [0x0, 0x1, 0x3, 0x7, 0xF];
        if (!in_array($sourceByte & 0x0F, $allowedMasterNibbles, true) ||
            !in_array(($sourceByte >> 4) & 0x0F, $allowedMasterNibbles, true)) {
            return;
        }

        $payloadLength = (int) $telegram[4];
        $crcPosition = 5 + $payloadLength;
        if ($payloadLength < 0 || $payloadLength > 16 || !isset($telegram[$crcPosition])) {
            return;
        }

        $masterData = array_slice($telegram, 0, $crcPosition);
        $calculatedCrc = $this->CalculateCrc($this->EscapeEbusBytes($masterData));
        if ($calculatedCrc !== (int) $telegram[$crcPosition]) {
            return;
        }

        $source = sprintf('%02X', $sourceByte);
        $destination = sprintf('%02X', (int) $telegram[1]);
        $entries = json_decode($this->ReadAttributeString('DiagObservedSourcesJSON'), true);
        if (!is_array($entries)) {
            $entries = [];
        }

        $now = date('d.m.Y H:i:s');
        $entry = isset($entries[$source]) && is_array($entries[$source]) ? $entries[$source] : [
            'count' => 0,
            'first' => $now,
            'last' => $now,
            'destination' => $destination,
            'example' => ''
        ];
        $entry['count'] = (int) ($entry['count'] ?? 0) + 1;
        $entry['last'] = $now;
        $entry['destination'] = $destination;
        $entry['example'] = $this->BytesToHex(array_slice($telegram, 0, min(12, count($telegram))));
        $entries[$source] = $entry;
        ksort($entries, SORT_STRING);

        $this->WriteAttributeString('DiagObservedSourcesJSON', json_encode($entries, JSON_THROW_ON_ERROR));

        $lines = [];
        foreach ($entries as $address => $data) {
            if (!is_array($data)) {
                continue;
            }
            $lines[] = sprintf(
                '%s = %dx | zuerst %s | zuletzt %s | letztes Ziel %s | Beispiel %s',
                $address,
                (int) ($data['count'] ?? 0),
                (string) ($data['first'] ?? '-'),
                (string) ($data['last'] ?? '-'),
                (string) ($data['destination'] ?? '-'),
                (string) ($data['example'] ?? '')
            );
        }
        $this->SetValue('DiagObservedSources', implode("\n", $lines));
    }

    /**
     * Passive HMU state telegram.
     * Confirmed on this installation:
     * B5 11 01 07 ... 0A <compressor modulation percent> ...
     *
     * @param array<int, int> $t
     */
    private function ProcessB511(array $t, int $p): void
    {
        if (($t[$p + 2] ?? -1) !== 0x01 ||
            ($t[$p + 3] ?? -1) !== 0x07 ||
            ($t[$p + 6] ?? -1) !== 0x0A ||
            !isset($t[$p + 7])) {
            return;
        }

        $percent = (int) $t[$p + 7];
        if ($percent < 0 || $percent > 100) {
            return;
        }

        $this->SetValue('HMUCompressorUtilization', (float) $percent);
    }

    /**
     * Passive hydraulic telegram.
     * Confirmed on this installation:
     * B5 12 06 13 <status> <phase 0C..0F> <flow low> <flow high> ...
     *
     * @param array<int, int> $t
     */
    private function ProcessB512(array $t, int $p): void
    {
        if (($t[$p + 2] ?? -1) !== 0x06 ||
            ($t[$p + 3] ?? -1) !== 0x13 ||
            !isset($t[$p + 5], $t[$p + 6], $t[$p + 7])) {
            return;
        }

        $phase = (int) $t[$p + 5];
        if (!in_array($phase, [0x0C, 0x0D, 0x0E, 0x0F], true)) {
            return;
        }

        $flow = $this->UInt16LE([$t[$p + 6], $t[$p + 7]]);
        if ($flow === null || $flow < 0 || $flow > 4000) {
            return;
        }

        $this->SetValue('HMUBuildingCircuitFlow', (float) $flow);
    }

    /**
     * Passive HMU RunData reader. The official HMU definition identifies
     * 54 02 00 5B 0D as current electrical power in watt (EXP/float LE).
     * No request is generated; an already present bus response is observed.
     *
     * @param array<int, int> $t
     */
    private function ProcessB509(array $t, int $p): void
    {
        $requestLength = $t[$p + 2] ?? -1;
        if ($requestLength !== 5 || !isset($t[$p + 7])) {
            return;
        }

        $requestID = $this->BytesToHex(array_slice($t, $p + 3, 5));
        if ($requestID !== '54 02 00 5B 0D') {
            return;
        }

        $responseLengthPos = $p + 3 + $requestLength + 2;
        if (!isset($t[$responseLengthPos])) {
            return;
        }

        $responseLength = (int) $t[$responseLengthPos];
        $responseStart = $responseLengthPos + 1;
        if ($responseLength < 8 || !isset($t[$responseStart + $responseLength - 1])) {
            return;
        }

        $powerW = $this->FloatLE(array_slice($t, $responseStart + 4, 4));
        if ($powerW === null || !is_finite($powerW) || $powerW < 0 || $powerW > 30000) {
            return;
        }

        $this->SetValue('HMUCurrentConsumedPower', $powerW / 1000.0);
        $this->UpdateThermalPower();
    }

    private function IncrementDiagnostic(string $ident): void
    {
        $this->SetValue($ident, (int) $this->GetValue($ident) + 1);
    }

    /** @param array<int, int> $bytes */
    private function BytesToHex(array $bytes): string
    {
        $parts = [];
        foreach ($bytes as $byte) {
            $parts[] = sprintf('%02X', $byte);
        }
        return implode(' ', $parts);
    }

    /**
     * Collect distinct B5-1A request payloads without transmitting anything.
     * The list is bounded so unexpected bus traffic cannot grow it forever.
     *
     * @param array<int, int> $t
     */
    private function UpdateB51ATypeDiagnostic(array $t, int $p): void
    {
        $requestLength = $t[$p + 2] ?? -1;
        if ($requestLength < 0 || $requestLength > 32) {
            return;
        }

        $lastRequestByte = $p + 2 + $requestLength;
        if ($requestLength > 0 && !isset($t[$lastRequestByte])) {
            return;
        }

        $request = $requestLength > 0
            ? array_slice($t, $p + 3, $requestLength)
            : [];
        $key = sprintf('%02X | %s', $requestLength, $this->BytesToHex($request));

        $stored = json_decode($this->ReadAttributeString('DiagB51ATypesJSON'), true);
        if (!is_array($stored)) {
            $stored = [];
        }

        if (isset($stored[$key])) {
            $stored[$key] = (int) $stored[$key] + 1;
        } elseif (count($stored) < 32) {
            $stored[$key] = 1;
        } else {
            return;
        }

        $json = json_encode($stored);
        if (is_string($json)) {
            $this->WriteAttributeString('DiagB51ATypesJSON', $json);
        }

        arsort($stored, SORT_NUMERIC);
        $lines = [];
        foreach ($stored as $type => $seen) {
            $lines[] = $type . ' = ' . (int) $seen . 'x';
        }
        $this->SetValue('DiagB51ATypes', implode("\n", $lines));
    }

    /**
     * Passive aroTHERM/VWZ control-loop diagnostic.
     * Observed format: B5 1A 03 04 <counter> <subcommand 32..36>.
     * The counter is deliberately ignored for grouping. Request and complete
     * response payload are retained so their data bytes can be mapped later.
     *
     * @param array<int, int> $t
     */
    private function UpdateB51AControlLoopDiagnostic(array $t, int $p): void
    {
        $requestLength = $t[$p + 2] ?? -1;
        if ($requestLength !== 3 ||
            ($t[$p + 3] ?? -1) !== 0x04 ||
            !isset($t[$p + 4], $t[$p + 5])) {
            return;
        }

        $subcommand = $t[$p + 5];
        if ($subcommand < 0x32 || $subcommand > 0x36) {
            return;
        }

        // Request is followed by request CRC, ACK, response length.
        $responseLengthPos = $p + 3 + $requestLength + 2;
        if (!isset($t[$responseLengthPos])) {
            return;
        }

        $responseLength = $t[$responseLengthPos];
        $responseStart = $responseLengthPos + 1;
        if ($responseLength < 0 ||
            ($responseLength > 0 && !isset($t[$responseStart + $responseLength - 1]))) {
            return;
        }

        $request = array_slice($t, $p + 3, $requestLength);
        $response = array_slice($t, $responseStart, $responseLength);
        $this->UpdateB51AChangeDiagnostic($subcommand, $response);
        $value = 'Request ' . $this->BytesToHex($request) .
            ' | Response ' . $this->BytesToHex($response);

        $this->SetValue(sprintf('DiagB51A%02X', $subcommand), $value);
    }

    /**
     * Remember every real payload-byte change for B5-1A 32..36.
     * Response byte 0 mirrors the rolling request counter and is intentionally
     * excluded. For each payload byte we retain last transition, min/max byte
     * value and the number of observed transitions.
     *
     * @param array<int, int> $response
     */
    private function UpdateB51AChangeDiagnostic(int $subcommand, array $response): void
    {
        $previousAll = json_decode($this->ReadAttributeString('DiagB51APreviousJSON'), true);
        if (!is_array($previousAll)) {
            $previousAll = [];
        }

        $subKey = sprintf('%02X', $subcommand);
        $previous = $previousAll[$subKey] ?? null;

        if (is_array($previous)) {
            $changes = json_decode($this->ReadAttributeString('DiagB51AChangesJSON'), true);
            if (!is_array($changes)) {
                $changes = [];
            }

            $maxBytes = min(count($previous), count($response));
            $changedNow = 0;
            for ($i = 1; $i < $maxBytes; $i++) {
                $old = (int) $previous[$i];
                $new = (int) $response[$i];
                if ($old === $new) {
                    continue;
                }

                $key = sprintf('%s:%02d', $subKey, $i);
                $entry = isset($changes[$key]) && is_array($changes[$key])
                    ? $changes[$key]
                    : [];

                $changes[$key] = [
                    'sub' => $subKey,
                    'byte' => $i,
                    'from' => $old,
                    'to' => $new,
                    'min' => isset($entry['min']) ? min((int) $entry['min'], $old, $new) : min($old, $new),
                    'max' => isset($entry['max']) ? max((int) $entry['max'], $old, $new) : max($old, $new),
                    'changes' => isset($entry['changes']) ? (int) $entry['changes'] + 1 : 1,
                ];
                $changedNow++;
            }

            if ($changedNow > 0) {
                $json = json_encode($changes);
                if (is_string($json)) {
                    $this->WriteAttributeString('DiagB51AChangesJSON', $json);
                }
                $this->SetValue(
                    'DiagB51AChangeCount',
                    (int) $this->GetValue('DiagB51AChangeCount') + $changedNow
                );
                $this->RenderB51AChanges($changes);
            }
        }

        $previousAll[$subKey] = array_values($response);
        $json = json_encode($previousAll);
        if (is_string($json)) {
            $this->WriteAttributeString('DiagB51APreviousJSON', $json);
        }
    }

    /** @param array<string, mixed> $changes */
    private function RenderB51AChanges(array $changes): void
    {
        ksort($changes, SORT_STRING);
        $lines = [];
        foreach ($changes as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $lines[] = sprintf(
                '%s Nutzbyte %02d: %02X -> %02X | Min %02X Max %02X | %dx',
                (string) ($entry['sub'] ?? '??'),
                (int) ($entry['byte'] ?? 0),
                (int) ($entry['from'] ?? 0),
                (int) ($entry['to'] ?? 0),
                (int) ($entry['min'] ?? 0),
                (int) ($entry['max'] ?? 0),
                (int) ($entry['changes'] ?? 0)
            );
        }
        $this->SetValue('DiagB51AChanges', implode("\n", $lines));
    }

    /**
     * Record the real six-byte B5-24 parameter IDs and their payload changes.
     * This is receive-only diagnosis; no request or control telegram is sent.
     * The lists are bounded to avoid unbounded instance-state growth.
     *
     * @param array<int, int> $t
     */
    private function UpdateB524TypeDiagnostic(array $t, int $p): void
    {
        $requestLength = $t[$p + 2] ?? -1;
        if ($requestLength !== 6 || !isset($t[$p + 8])) {
            return;
        }

        $request = array_slice($t, $p + 3, 6);
        if (count($request) !== 6) {
            return;
        }

        $id = str_replace(' ', '', $this->BytesToHex($request));
        // Keep everything following the six request bytes. This also covers
        // passive/master frames that do not contain the paired response layout
        // used by the older capture script.
        $rawTail = array_slice($t, $p + 3 + $requestLength);
        $rawTailHex = $this->BytesToHex($rawTail);

        // Decode the response only when this concrete frame actually contains
        // the familiar CRC/ACK + length + response arrangement.
        $responseHex = '';
        $payloadHex = '';
        $responseLengthPos = $p + 3 + $requestLength + 2;
        if (isset($t[$responseLengthPos])) {
            $responseLength = (int) $t[$responseLengthPos];
            $responseStart = $responseLengthPos + 1;
            if (
                $responseLength >= 0
                && $responseLength <= 64
                && ($responseLength === 0 || isset($t[$responseStart + $responseLength - 1]))
            ) {
                $response = array_slice($t, $responseStart, $responseLength);
                $payload = $responseLength > 4 ? array_slice($response, 4) : [];
                $responseHex = $this->BytesToHex($response);
                $payloadHex = $this->BytesToHex($payload);
            }
        }

        $stored = json_decode($this->ReadAttributeString('DiagB524TypesJSON'), true);
        if (!is_array($stored)) {
            $stored = [];
        }
        if (!isset($stored[$id]) && count($stored) >= 64) {
            return;
        }

        $previousRaw = isset($stored[$id]['raw']) ? (string) $stored[$id]['raw'] : null;
        $seen = isset($stored[$id]['seen']) ? (int) $stored[$id]['seen'] + 1 : 1;
        $changed = $previousRaw !== null && $previousRaw !== $rawTailHex;
        $stored[$id] = [
            'seen' => $seen,
            'time' => time(),
            'raw' => $rawTailHex,
            'response' => $responseHex,
            'payload' => $payloadHex
        ];

        $json = json_encode($stored);
        if (is_string($json)) {
            $this->WriteAttributeString('DiagB524TypesJSON', $json);
        }

        if ($changed) {
            $changes = json_decode($this->ReadAttributeString('DiagB524ChangesJSON'), true);
            if (!is_array($changes)) {
                $changes = [];
            }
            $changes[] = [
                'time' => time(),
                'id' => $id,
                'old' => $previousRaw,
                'new' => $rawTailHex
            ];
            if (count($changes) > 80) {
                $changes = array_slice($changes, -80);
            }
            $changesJson = json_encode($changes);
            if (is_string($changesJson)) {
                $this->WriteAttributeString('DiagB524ChangesJSON', $changesJson);
            }
            $this->SetValue(
                'DiagB524ChangeCount',
                (int) $this->GetValue('DiagB524ChangeCount') + 1
            );
            $this->RenderB524Changes($changes);
        }

        ksort($stored, SORT_STRING);
        $lines = [];
        foreach ($stored as $storedID => $entry) {
            $lines[] = sprintf(
                '%s = %dx | %s | Rest %s | Payload %s | Response %s',
                $storedID,
                (int) ($entry['seen'] ?? 0),
                isset($entry['time']) ? date('d.m.Y H:i:s', (int) $entry['time']) : '-',
                (string) ($entry['raw'] ?? ''),
                (string) ($entry['payload'] ?? ''),
                (string) ($entry['response'] ?? '')
            );
        }
        $this->SetValue('DiagB524Types', implode("\n", $lines));
    }

    /** @param array<int, array<string, mixed>> $changes */
    private function RenderB524Changes(array $changes): void
    {
        $lines = [];
        foreach ($changes as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $lines[] = sprintf(
                '%s | ID %s | ALT %s | NEU %s',
                isset($entry['time']) ? date('d.m.Y H:i:s', (int) $entry['time']) : '-',
                (string) ($entry['id'] ?? ''),
                (string) ($entry['old'] ?? ''),
                (string) ($entry['new'] ?? '')
            );
        }
        $this->SetValue('DiagB524Changes', implode("\n", $lines));
    }

    /**
     * Collect passive B5-14 request IDs and their latest complete response.
     * Known aroTHERM sensor traffic commonly uses a five-byte request such as
     * 05 28 03 FF FF, where 28 identifies the requested value. This function
     * deliberately records the real bus data before any datatype is assumed.
     *
     * @param array<int, int> $t
     */
    private function UpdateB514TypeDiagnostic(array $t, int $p): void
    {
        $requestLength = $t[$p + 2] ?? -1;
        if ($requestLength < 1 || $requestLength > 32) {
            return;
        }

        $lastRequestByte = $p + 2 + $requestLength;
        if (!isset($t[$lastRequestByte])) {
            return;
        }

        $request = array_slice($t, $p + 3, $requestLength);
        $responseLengthPos = $p + 3 + $requestLength + 2;
        if (!isset($t[$responseLengthPos])) {
            return;
        }

        $responseLength = $t[$responseLengthPos];
        $responseStart = $responseLengthPos + 1;
        if ($responseLength > 0 && !isset($t[$responseStart + $responseLength - 1])) {
            return;
        }
        $response = array_slice($t, $responseStart, $responseLength);

        // For the known 05 <id> 03 FF FF family use the ID as the stable key.
        // Unknown layouts remain distinguishable by their complete request.
        if ($requestLength >= 2 && $request[0] === 0x05) {
            $key = sprintf('ID %02X', $request[1]);
        } else {
            $key = sprintf('REQ %02X | %s', $requestLength, $this->BytesToHex($request));
        }

        $stored = json_decode($this->ReadAttributeString('DiagB514TypesJSON'), true);
        if (!is_array($stored)) {
            $stored = [];
        }

        if (!isset($stored[$key]) && count($stored) >= 64) {
            return;
        }

        $seen = isset($stored[$key]['seen']) ? (int) $stored[$key]['seen'] + 1 : 1;
        $stored[$key] = [
            'seen' => $seen,
            'request' => $this->BytesToHex($request),
            'response' => $this->BytesToHex($response),
        ];

        $json = json_encode($stored);
        if (is_string($json)) {
            $this->WriteAttributeString('DiagB514TypesJSON', $json);
        }

        ksort($stored, SORT_STRING);
        $lines = [];
        foreach ($stored as $type => $entry) {
            $lines[] = sprintf(
                '%s = %dx | Request %s | Response %s',
                $type,
                (int) ($entry['seen'] ?? 0),
                (string) ($entry['request'] ?? ''),
                (string) ($entry['response'] ?? '')
            );
        }
        $this->SetValue('DiagB514Types', implode("\n", $lines));
    }

    /**
     * B5 24 request: B5 24 06 + six-byte parameter id + CRC/ACK + response.
     * Response payload contains four header bytes before the value.
     *
     * @param array<int, int> $t
     */
    private function ProcessB524(array $t, int $p): void
    {
        $requestLength = $t[$p + 2] ?? -1;
        if ($requestLength !== 6 || !isset($t[$p + 8])) {
            return;
        }

        $id = '';
        for ($i = 0; $i < 6; $i++) {
            $id .= sprintf('%02X', $t[$p + 3 + $i]);
        }

        $responseLengthPos = $p + 3 + $requestLength + 2;
        if (!isset($t[$responseLengthPos])) {
            return;
        }

        $responseLength = $t[$responseLengthPos];
        $responseStart = $responseLengthPos + 1;
        if ($responseLength < 5 || !isset($t[$responseStart + $responseLength - 1])) {
            return;
        }

        // Known 4-byte EXP (IEEE754 LE) values.
        $floatMap = [
            '020000004B00' => ['SystemFlowTemperature', 'temperature'],
            '020000007300' => ['OutsideTemperature', 'temperature'],
            '020001000400' => ['HotWaterTarget', 'temperature'],
            '020001000500' => ['HotWaterActual', 'temperature'],
            '020001000800' => ['HotWaterFlow', 'temperature'],
            '020002000700' => ['HeatingCircuit1TargetFlow', 'temperature'],
            '020002000800' => ['HeatingCircuit1Flow', 'temperature'],
            '020002000F00' => ['HeatingCurve1', 'float'],
        ];

        if (isset($floatMap[$id]) && $responseLength >= 8) {
            $value = $this->FloatLE(array_slice($t, $responseStart + 4, 4));
            if ($value !== null && is_finite($value)) {
                $this->SetValue($floatMap[$id][0], $value);
            }
            return;
        }

        // WaterPressure is pressv -> EXP, value in bar.
        if ($id === '020000003900' && $responseLength >= 8) {
            $value = $this->FloatLE(array_slice($t, $responseStart + 4, 4));
            if ($value !== null && is_finite($value)) {
                $this->SetValue('WaterPressure', $value);
            }
            return;
        }

        // energy4 -> ULG = unsigned 32 bit, low byte first, kWh.
        if (($id === '020000005700' || $id === '020000005800') && $responseLength >= 8) {
            $value = $this->UInt32LE(array_slice($t, $responseStart + 4, 4));
            if ($value !== null) {
                $this->SetValue($id === '020000005700' ? 'EnergyHeating' : 'EnergyHotWater', (float) $value);
            }
        }
    }

    /**
     * Normal HMU live monitor (08.hmu.tsp): B5 1A 04 05 counter 32 subId.
     * First three response bytes are ignored by the Vaillant definition.
     * Handles matching passive traffic and the whitelisted active reads.
     *
     * @param array<int, int> $t
     */
    private function ProcessB51A(array $t, int $p): void
    {
        if (($t[$p + 2] ?? -1) !== 4 ||
            ($t[$p + 3] ?? -1) !== 0x05 ||
            ($t[$p + 5] ?? -1) !== 0x32 ||
            !isset($t[$p + 6])) {
            return;
        }

        $subId = $t[$p + 6];
        $responseLengthPos = $p + 3 + 4 + 2;
        if (!isset($t[$responseLengthPos])) {
            return;
        }

        $responseLength = $t[$responseLengthPos];
        $responseStart = $responseLengthPos + 1;
        if ($responseLength < 4 || !isset($t[$responseStart + $responseLength - 1])) {
            return;
        }

        $payload = array_slice($t, $responseStart + 3, $responseLength - 3);

        switch ($subId) {
            case 0x1C:
                $this->SetD2C('HMUTargetHeatingCircuit', $payload);
                break;
            case 0x1F:
                $this->SetD2C('HMUTargetFlow', $payload);
                break;
            case 0x20:
                $this->SetD2C('HMUFlowTemperature', $payload);
                break;
            case 0x21:
                $value = $this->Int16LE($payload);
                if ($value !== null) {
                    $this->SetValue('HMUEnergyIntegral', (float) $value);
                }
                break;
            case 0x22:
                $this->SetD2C('HMUSourceInputTemperature', $payload);
                break;
            case 0x23:
                $this->SetUIN10('HMUCurrentEnvironmentalPower', $payload);
                $this->UpdateThermalPower();
                break;
            case 0x24:
                $this->SetUIN10('HMUCurrentConsumedPower', $payload);
                $this->UpdateThermalPower();
                break;
            case 0x25:
                $this->SetCompressorPercent($payload);
                break;
            case 0x26:
                $this->SetD2C('HMUAirIntakeTemperature', $payload);
                break;
            case 0x27:
                $this->SetD2C('HMUSourceOutputTemperature', $payload);
                break;
            case 0x3C:
                $value = $this->UInt16LE($payload);
                if ($value !== null) {
                    $this->SetValue('HMUBuildingCircuitFlow', (float) $value);
                }
                break;
            case 0x3D:
                $value = $this->Int16LE($payload);
                if ($value !== null) {
                    $this->SetValue('HMUFlowPressure', $value / 4.0);
                }
                break;
            case 0x3E:
                $value = $this->Int16LE($payload);
                if ($value !== null) {
                    $this->SetValue('HMUSourcePressure', $value / 4.0);
                }
                break;
        }
    }

    /** @param array<int, int> $bytes */
    private function FloatLE(array $bytes): ?float
    {
        if (count($bytes) < 4) {
            return null;
        }
        $binary = chr($bytes[0]) . chr($bytes[1]) . chr($bytes[2]) . chr($bytes[3]);
        $value = unpack('gvalue', $binary);
        return isset($value['value']) ? (float) $value['value'] : null;
    }

    /** @param array<int, int> $bytes */
    private function UInt16LE(array $bytes): ?int
    {
        if (count($bytes) < 2) {
            return null;
        }
        return $bytes[0] | ($bytes[1] << 8);
    }

    /** @param array<int, int> $bytes */
    private function Int16LE(array $bytes): ?int
    {
        $value = $this->UInt16LE($bytes);
        if ($value === null) {
            return null;
        }
        return $value >= 0x8000 ? $value - 0x10000 : $value;
    }

    /** @param array<int, int> $bytes */
    private function UInt32LE(array $bytes): ?int
    {
        if (count($bytes) < 4) {
            return null;
        }
        return $bytes[0] | ($bytes[1] << 8) | ($bytes[2] << 16) | ($bytes[3] << 24);
    }

    /** @param array<int, int> $bytes */
    private function SetD2C(string $ident, array $bytes): void
    {
        $value = $this->Int16LE($bytes);
        if ($value === null) {
            return;
        }
        $decoded = $value / 16.0;
        // Reject eBUS replacement/error values (for example about -1005 °C)
        // before they can be written to and archived by IP-Symcon.
        if ($decoded < -60.0 || $decoded > 120.0) {
            return;
        }
        $this->SetValue($ident, $decoded);
    }

    /** @param array<int, int> $bytes */
    private function SetD1BDiv10(string $ident, array $bytes): void
    {
        if (!isset($bytes[0])) {
            return;
        }
        $value = $bytes[0] >= 0x80 ? $bytes[0] - 0x100 : $bytes[0];
        $this->SetValue($ident, $value / 10.0);
    }

    /** @param array<int, int> $bytes */
    private function SetUIN10(string $ident, array $bytes): void
    {
        if (!isset($bytes[0])) {
            return;
        }
        if (isset($bytes[1])) {
            $value = $this->UInt16LE($bytes);
        } else {
            $value = $bytes[0] >= 0x80 ? $bytes[0] - 0x100 : $bytes[0];
        }
        if ($value === null) {
            return;
        }
        $decoded = $value / 10.0;
        // 30 kW is deliberately a generous plausibility ceiling for this
        // installation. It rejects known replacement values around 78 kW.
        if ($decoded < 0 || $decoded > 30.0) {
            return;
        }
        $this->SetValue($ident, $decoded);
    }

    /** @param array<int, int> $bytes */
    private function SetCompressorPercent(array $bytes): void
    {
        if (!isset($bytes[0])) {
            return;
        }

        // Current HMU definitions use SCH (one signed byte). Some hardware
        // variants expose UIN/16 instead, so accept that only as a bounded
        // fallback. Both paths remain strictly receive-only.
        $signed = $bytes[0] >= 0x80 ? $bytes[0] - 0x100 : $bytes[0];
        if ($signed >= 0 && $signed <= 100) {
            $this->SetValue('HMUCompressorUtilization', (float) $signed);
            return;
        }

        $raw = $this->UInt16LE($bytes);
        if ($raw !== null) {
            $percent = $raw / 16.0;
            if ($percent >= 0 && $percent <= 100) {
                $this->SetValue('HMUCompressorUtilization', $percent);
            }
        }
    }

    private function UpdateThermalPower(): void
    {
        $environmentalID = @IPS_GetObjectIDByIdent('HMUCurrentEnvironmentalPower', $this->InstanceID);
        $consumedID = @IPS_GetObjectIDByIdent('HMUCurrentConsumedPower', $this->InstanceID);
        if ($environmentalID === false || $consumedID === false) {
            return;
        }

        $environmentalInfo = IPS_GetVariable($environmentalID);
        $consumedInfo = IPS_GetVariable($consumedID);
        $environmentalUpdated = (int) ($environmentalInfo['VariableUpdated'] ?? 0);
        $consumedUpdated = (int) ($consumedInfo['VariableUpdated'] ?? 0);
        $now = time();

        // Never combine a fresh register with an old value from another poll.
        if (
            $environmentalUpdated <= 0
            || $consumedUpdated <= 0
            || ($now - $environmentalUpdated) > 120
            || ($now - $consumedUpdated) > 120
            || abs($environmentalUpdated - $consumedUpdated) > 120
        ) {
            return;
        }

        $environmental = (float) GetValue($environmentalID);
        $consumed = (float) GetValue($consumedID);
        if ($environmental < 0 || $environmental > 30.0 || $consumed < 0 || $consumed > 30.0) {
            return;
        }
        $thermal = $environmental + $consumed;
        if ($thermal >= 0 && $thermal <= 30.0) {
            $this->SetValue('HMUCurrentYieldPower', $thermal);
        }
    }
}
