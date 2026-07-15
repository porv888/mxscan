<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Compatibility;

use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptNativeResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptProtocolStatus;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptStates;

final class TlsRptLegacyPayloadAdapter
{
    public function __construct(
        private TlsRptNativeAnalysisPayload $analysisPayload = new TlsRptNativeAnalysisPayload(),
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toResultJsonTlsRpt(TlsRptNativeResult $native): array
    {
        $analysis = $this->analysisPayload->fromNative($native);

        return [
            'status' => $this->legacyStatus($native),
            'valid' => $native->protocolStatus === TlsRptProtocolStatus::VALID,
            'protocol_status' => $analysis['protocol_status'],
            'risk_status' => $analysis['risk_status'],
            'ui_state' => $analysis['state'],
            'summary' => $analysis['summary'],
            'analysis' => $analysis,
        ];
    }

    /**
     * @return array{status: string, data: ?string}
     */
    public function toDnsRecordCompat(TlsRptNativeResult $native): array
    {
        if ($native->protocolStatus === TlsRptProtocolStatus::NONE) {
            return ['status' => 'missing', 'data' => null];
        }

        return [
            'status' => 'found',
            'data' => $native->rawRecord,
        ];
    }

    private function legacyStatus(TlsRptNativeResult $native): string
    {
        return match ($native->state) {
            TlsRptStates::PASS => 'ok',
            TlsRptStates::WARNING => 'warning',
            TlsRptStates::FAIL, TlsRptStates::MISSING => 'error',
            default => 'unknown',
        };
    }
}
