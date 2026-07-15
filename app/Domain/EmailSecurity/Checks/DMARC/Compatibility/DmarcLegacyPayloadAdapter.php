<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Compatibility;

use App\Domain\EmailSecurity\Checks\DMARC\DmarcNativeResult;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcProtocolStatus;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcStates;

final class DmarcLegacyPayloadAdapter
{
    public function __construct(
        private DmarcNativeAnalysisPayload $analysisPayload = new DmarcNativeAnalysisPayload(),
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toResultJsonDmarc(DmarcNativeResult $native): array
    {
        $analysis = $this->analysisPayload->fromNative($native);

        return [
            'record' => $native->rawRecord,
            'status' => $this->legacyStatus($native),
            'valid' => $native->protocolStatus === DmarcProtocolStatus::VALID,
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
    public function toDnsRecordCompat(DmarcNativeResult $native): array
    {
        if ($native->protocolStatus === DmarcProtocolStatus::NONE) {
            return ['status' => 'missing', 'data' => null];
        }

        return [
            'status' => 'found',
            'data' => $native->rawRecord,
        ];
    }

    private function legacyStatus(DmarcNativeResult $native): string
    {
        return match ($native->state) {
            DmarcStates::PASS => 'ok',
            DmarcStates::WARNING => 'warning',
            DmarcStates::FAIL, DmarcStates::MISSING => 'error',
            default => 'unknown',
        };
    }
}
