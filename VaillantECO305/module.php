<?php

declare(strict_types=1);

/**
 * Vaillant ECO305 eBUS decoder for IP-Symcon 9.
 *
 * SAFETY DESIGN:
 * - Passive decoding remains enabled for all existing values.
 * - Optional active traffic is restricted to two hard-coded HMU read requests.
 * - No EnableTest messages.
 * - No compressor, pump, valve, service or safety commands.
 * - No caller-controlled raw messages; only two fixed read telegrams exist.
 * - All module status variables are logged locally by IP-Symcon Archive Control.
 *
 * ECO305 mode: Enhanced, TCP server.
 */
class VaillantECO305 extends IPSModuleStrict
{
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
    private const OWN_MASTER = 0x31;
    private const HMU_ADDRESS = 0x08;

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
        $this->RegisterVariableFloat('HMUBuildingCircuitFlow', 'Durchfluss Heizkreis [l/h]', '', 290);
        $this->RegisterVariableFloat('HMUFlowPressure', 'HMU Anlagendruck [bar]', '', 300);
        $this->RegisterVariableFloat('HMUSourcePressure', 'HMU Quelldruck [bar]', '', 310);

        // Passive protocol diagnostics. Deliberately not archived.
        $this->RegisterVariableInteger('DiagB524Count', 'Diagnose: B5-24 Telegramme gesehen', '', 900);
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

        $this->RegisterVariableString('PowerReadStatus', 'Leistungsabfrage Status', '', 1040);
        $this->RegisterVariableString('PowerReadLastResponse', 'Leistungsabfrage letzte Antwort', '', 1050);
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();
        $enabled = $this->ReadPropertyBoolean('EnableActivePowerPolling');
        $interval = max(30, $this->ReadPropertyInteger('PowerPollIntervalSeconds'));
        $this->SetTimerInterval('PowerPoll', $enabled ? $interval * 1000 : 0);
        $this->SetSummary($enabled
            ? 'ECO305 Enhanced - Telemetrie lesen - V1.3'
            : 'ECO305 Enhanced - passiv - V1.3');

        $this->SetBuffer('PowerReadState', '');
        $this->SetBuffer('EnhancedRxPartial', '');
        $this->SetBuffer('PassiveFrame', '');
        $this->SetBuffer('PassiveEscape', '0');
        $this->SetBuffer('PassiveSynchronized', '0');
        // The ECO305 connection is already delivering enhanced telegrams.
        // Some ECO305 firmware does not answer a repeated INIT on an existing
        // TCP session, therefore active reads start directly on this stream.
        $this->SetBuffer('EnhancedInitialized', '1');
        if ($this->GetBuffer('NextPowerRegister') === '') {
            $this->SetBuffer('NextPowerRegister', 'environmental');
        }

        if ($enabled) {
            $this->SetValue('PowerReadStatus', 'Leistungsabfrage wird gestartet');
            $this->StartPowerRead();
        } else {
            $this->SetValue('PowerReadStatus', 'Deaktiviert – rein passiver Empfang');
        }
        $this->EnableArchiveLogging();
    }

    public function GetConfigurationForm(): string
    {
        return json_encode([
            'elements' => [
                [
                    'type'    => 'CheckBox',
                    'name'    => 'EnableActivePowerPolling',
                    'caption' => 'Leistungswerte aktiv abfragen (ausschließlich lesen)'
                ],
                [
                    'type'    => 'NumberSpinner',
                    'name'    => 'PowerPollIntervalSeconds',
                    'caption' => 'Abfrageintervall je Register (Sekunden)',
                    'minimum' => 30,
                    'maximum' => 3600,
                    'suffix'  => ' s'
                ],
                [
                    'type'    => 'Label',
                    'caption' => 'Es werden ausschließlich die HMU-Live-Monitor-Leseregister 32 23 (Umweltleistung) und 32 24 (Aufnahmeleistung) abgefragt. Keine Test- oder Stellbefehle.'
                ]
            ],
            'actions' => [
                [
                    'type'    => 'Button',
                    'caption' => 'Leistungsabfrage jetzt starten',
                    'onClick' => 'VECO_PollPower($id);'
                ]
            ]
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
                strncmp($object['ObjectIdent'], 'PowerRead', 9) === 0) {
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
            $this->SetValue('PowerReadStatus', 'ECO305 initialisiert');
            if ($this->ReadPropertyBoolean('EnableActivePowerPolling')) {
                $this->StartPowerRead();
            }
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

    /**
     * Start one whitelisted HMU read. Calls alternate between environmental
     * power (32 23) and consumed electrical power (32 24).
     */
    public function PollPower(): void
    {
        if (!$this->ReadPropertyBoolean('EnableActivePowerPolling')) {
            return;
        }

        $state = $this->ReadPowerState();
        if (($state['active'] ?? false) === true) {
            $started = (int) ($state['started'] ?? 0);
            if ($started > 0 && (time() - $started) <= 15) {
                return;
            }
            $this->AbortPowerRead('Vorherige Abfrage nach Zeitüberschreitung verworfen');
            return;
        }

        $this->StartPowerRead();
    }

    private function StartPowerRead(): void
    {
        $current = $this->ReadPowerState();
        if (($current['active'] ?? false) === true) {
            return;
        }

        $key = $this->GetBuffer('NextPowerRegister');
        if ($key !== 'consumed') {
            $key = 'environmental';
        }
        $subId = $key === 'environmental' ? 0x23 : 0x24;

        // Fixed read-only live-monitor telegram: source 31, HMU 08, B5 1A,
        // request 05 00 32 23/24. No caller-supplied raw bytes are accepted.
        $master = [
            self::OWN_MASTER,
            self::HMU_ADDRESS,
            0xB5,
            0x1A,
            0x04,
            0x05,
            0x00,
            0x32,
            $subId
        ];
        $masterWire = $this->EscapeEbusBytes($master);
        $crc = $this->CalculateCrc($masterWire);
        $txWire = array_merge(array_slice($masterWire, 1), $this->EscapeEbusBytes([$crc]));

        $state = [
            'active'           => true,
            'started'          => time(),
            'stage'            => 'wait_start',
            'key'              => $key,
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
        $this->SetValue('PowerReadStatus', $key === 'environmental'
            ? 'Umweltleistung wird gelesen'
            : 'Aufnahmeleistung wird gelesen');

        $this->SendEnhanced(0x02, self::OWN_MASTER);
    }

    private function HandlePowerProtocolEvent(int $command, int $value): void
    {
        $state = $this->ReadPowerState();
        if (($state['active'] ?? false) !== true) {
            return;
        }

        if ($command === self::ENH_RES_FAILED) {
            $this->AbortPowerRead('Buszugriff belegt – nächster Versuch folgt');
            return;
        }
        if ($command === self::ENH_RES_ERROR_EBUS || $command === self::ENH_RES_ERROR_HOST) {
            $this->AbortPowerRead('ECO305 Kommunikationsfehler ' . sprintf('%02X', $value));
            return;
        }

        $stage = (string) ($state['stage'] ?? '');
        if ($stage === 'wait_start') {
            if ($command !== self::ENH_RES_STARTED || $value !== self::OWN_MASTER) {
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

        if ($stage === 'wait_command_ack') {
            if ($value !== self::EBUS_ACK) {
                $this->AbortPowerRead(
                    'HMU hat die Leseabfrage nicht bestätigt (Antwort ' . sprintf('%02X', $value) . ')'
                );
                return;
            }
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
                $this->AbortPowerRead('Ungültige Escape-Sequenz in HMU-Antwort');
                return;
            }
            $state['responseEscape'] = false;
        } elseif ($raw === self::EBUS_ESC) {
            $state['responseEscape'] = true;
            $this->WritePowerState($state);
            return;
        } elseif ($raw === self::EBUS_SYN) {
            $this->AbortPowerRead('HMU-Antwort vorzeitig beendet');
            return;
        } else {
            $logical[] = $raw;
        }

        if (count($logical) === 1) {
            $payloadLength = (int) $logical[0];
            if ($payloadLength < 4 || $payloadLength > 32) {
                $this->AbortPowerRead('Unplausible HMU-Antwortlänge');
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

        if ($valid && $this->DecodeActivePowerResponse($key, $logical)) {
            $this->SetValue('PowerReadLastResponse', strtoupper(implode(' ', array_map(
                static fn (int $byte): string => sprintf('%02x', $byte),
                $logical
            ))));
            $this->SetValue('PowerReadStatus', $key === 'environmental'
                ? 'Umweltleistung erfolgreich gelesen'
                : 'Aufnahmeleistung erfolgreich gelesen');
            $this->SetBuffer('NextPowerRegister', $key === 'environmental' ? 'consumed' : 'environmental');
        } elseif (!$valid) {
            $this->SetValue('PowerReadStatus', 'HMU-Antwort mit ungültiger Prüfsumme');
        }

        $this->SetBuffer('PowerReadState', '');
    }

    /** @param array<int, int> $logical */
    private function DecodeActivePowerResponse(string $key, array $logical): bool
    {
        if (count($logical) < 5) {
            $this->SetValue('PowerReadStatus', 'HMU-Antwort enthält keinen Leistungswert');
            return false;
        }

        // Byte 0 is the slave length; the first three payload bytes are
        // ignored by the official Vaillant HMU definition.
        $payload = array_slice($logical, 4);
        $value = null;
        if (count($payload) >= 2) {
            $raw = $payload[0] | ($payload[1] << 8);
            $value = $raw / 10.0;
        } elseif (isset($payload[0])) {
            $raw = $payload[0] >= 0x80 ? $payload[0] - 0x100 : $payload[0];
            $value = $raw / 10.0;
        }

        if ($value === null || $value < 0.0 || $value > 100.0) {
            $this->SetValue('PowerReadStatus', 'HMU-Leistungswert unplausibel');
            return false;
        }

        if ($key === 'environmental') {
            $this->SetValue('HMUCurrentEnvironmentalPower', $value);
        } elseif ($key === 'consumed') {
            $this->SetValue('HMUCurrentConsumedPower', $value);
        } else {
            return false;
        }
        $this->UpdateThermalPower();
        return true;
    }

    private function AbortPowerRead(string $message): void
    {
        $state = $this->ReadPowerState();
        $stage = (string) ($state['stage'] ?? '');
        $wasActive = ($state['active'] ?? false) === true;
        $this->SetValue('PowerReadStatus', $message);
        $this->SetBuffer('PowerReadState', '');

        if ($wasActive) {
            // Release an arbitration still in progress, or end a transaction
            // already won. This is the only non-read payload used here and is
            // the mandatory eBUS synchronisation symbol, not a device command.
            $this->SendEnhanced($stage === 'wait_start' ? 0x02 : 0x01, self::EBUS_SYN);
        }
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
     * Handles matching passive traffic and the two whitelisted active reads.
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
        if ($value !== null) {
            $this->SetValue($ident, $value / 16.0);
        }
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
        if ($decoded < 0 || $decoded > 100.0) {
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
        $environmental = (float) $this->GetValue('HMUCurrentEnvironmentalPower');
        $consumed = (float) $this->GetValue('HMUCurrentConsumedPower');
        $thermal = $environmental + $consumed;
        if ($thermal >= 0 && $thermal <= 150.0) {
            $this->SetValue('HMUCurrentYieldPower', $thermal);
        }
    }
}
