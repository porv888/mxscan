<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Compatibility;

use App\Domain\EmailSecurity\Checks\Bimi\BimiNativeResult;
use App\Domain\EmailSecurity\Checks\Bimi\BimiProtocolStatus;
use App\Domain\EmailSecurity\Checks\Bimi\BimiStates;

final class BimiLegacyPayloadAdapter
{
    public function __construct(
        private BimiNativeAnalysisPayload $analysisPayload = new BimiNativeAnalysisPayload(),
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toResultJsonBimi(BimiNativeResult $native): array
    {
        $analysis = $this->analysisPayload->fromNative($native);

        return [
            'status' => $this->legacyStatus($native),
            'valid' => $native->protocolStatus === BimiProtocolStatus::VALID,
            'protocol_status' => $analysis['protocol_status'],
            'readiness_status' => $analysis['readiness_status'],
            'evidence_status' => $analysis['evidence_status'],
            'risk_status' => $analysis['risk_status'],
            'ui_state' => $analysis['state'],
            'summary' => $analysis['summary'],
            'analysis' => $analysis,
        ];
    }

    /**
     * @return array{status: string, data: ?array<string, mixed>}
     */
    public function toDnsRecordCompat(BimiNativeResult $native): array
    {
        if (in_array($native->protocolStatus, [BimiProtocolStatus::NONE, BimiProtocolStatus::TEMPERROR], true)) {
            return ['status' => 'missing', 'data' => null];
        }

        if ($native->protocolStatus === BimiProtocolStatus::DECLINED) {
            return [
                'status' => 'found',
                'data' => [
                    'raw_record' => $native->rawRecord,
                    'declined' => true,
                ],
            ];
        }

        if ($native->state === BimiStates::WARNING || $native->state === BimiStates::FAIL) {
            return [
                'status' => 'partial',
                'data' => [
                    'raw_record' => $native->rawRecord,
                    'protocol_status' => $native->protocolStatus,
                    'readiness_status' => $native->readinessStatus,
                ],
            ];
        }

        return [
            'status' => 'found',
            'data' => [
                'raw_record' => $native->rawRecord,
                'protocol_status' => $native->protocolStatus,
                'readiness_status' => $native->readinessStatus,
            ],
        ];
    }

    private function legacyStatus(BimiNativeResult $native): string
    {
        return match ($native->state) {
            BimiStates::PASS => 'ok',
            BimiStates::WARNING, BimiStates::DECLINED => 'warning',
            BimiStates::FAIL, BimiStates::MISSING => 'error',
            default => 'unknown',
        };
    }
}
