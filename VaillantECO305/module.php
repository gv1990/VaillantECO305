<?php

declare(strict_types=1);

/**
 * Vaillant ECO305 passive eBUS decoder for IP-Symcon 9.
 *
 * SAFETY DESIGN:
 * - Receive only. There is deliberately NO SendDataToParent() call.
 * - No EnableTest messages.
 * - No compressor, pump, valve, service or safety commands.
 * - Compressor/HMU telemetry is decoded only when it already appears on eBUS.
 * - All module status variables are logged locally by IP-Symcon Archive Control.
 *
 * ECO305 mode: Enhanced, TCP server.
 */
class VaillantECO305 extends IPSModuleStrict
{
    private const ECO_SYN = "\xC6\xAA";

    public function Create(): void
    {
        parent::Create();

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
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();
        $this->SetSummary('ECO305 Enhanced - nur lesen');
        $this->EnableArchiveLogging();
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
            if (strncmp($object['ObjectIdent'], 'Diag', 4) === 0) {
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

        $storedHex = $this->GetBuffer('RxEnhanced');
        $stored = $storedHex !== '' ? hex2bin($storedHex) : '';
        if ($stored === false) {
            $stored = '';
        }

        $data = $stored . $incoming;
        $parts = explode(self::ECO_SYN, $data);

        if (count($parts) < 2) {
            if (strlen($data) > 8192) {
                $data = substr($data, -8192);
            }
            $this->SetBuffer('RxEnhanced', bin2hex($data));
            return '';
        }

        // Anything before the first ECO SYN is an incomplete predecessor.
        // Process only telegrams that are closed by the next SYN.
        for ($i = 1, $n = count($parts) - 1; $i < $n; $i++) {
            if ($parts[$i] === '') {
                continue;
            }

            $telegram = $this->DecodeEnhanced($parts[$i]);
            if ($telegram !== []) {
                $this->ProcessTelegram($telegram);
            }
        }

        $rest = self::ECO_SYN . $parts[count($parts) - 1];
        if (strlen($rest) > 8192) {
            $rest = substr($rest, -8192);
        }
        $this->SetBuffer('RxEnhanced', bin2hex($rest));

        return '';
    }

    /** @return array<int, int> */
    private function DecodeEnhanced(string $raw): array
    {
        $out = [];
        $len = strlen($raw);

        for ($i = 0; $i < $len; $i++) {
            $b1 = ord($raw[$i]);

            if (($b1 & 0x80) === 0) {
                $out[] = $b1;
                continue;
            }

            if (($i + 1) >= $len) {
                break;
            }

            $b2 = ord($raw[++$i]);
            if (($b2 & 0x40) !== 0) {
                [$b1, $b2] = [$b2, $b1];
            }

            $out[] = ($b2 & 0x3F) | (($b1 & 0x03) << 6);
        }

        return $out;
    }

    /** @param array<int, int> $telegram */
    private function ProcessTelegram(array $telegram): void
    {
        $count = count($telegram);
        for ($p = 0; $p <= $count - 3; $p++) {
            if ($telegram[$p] !== 0xB5) {
                continue;
            }

            if (($telegram[$p + 1] ?? -1) === 0x24) {
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
     * This method only watches already-present telegrams.
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
                $this->SetD1BDiv10('HMUCurrentYieldPower', $payload);
                break;
            case 0x24:
                $this->SetD1BDiv10('HMUCurrentConsumedPower', $payload);
                break;
            case 0x25:
                $this->SetD2C('HMUCompressorUtilization', $payload);
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
}
