<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Compatibility;

use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsNativeResult;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsProtocolStatus;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsStates;

final class MtaStsLegacyPayloadAdapter
{
    public function __construct(
        private MtaStsNativeAnalysisPayload $analysisPayload = new MtaStsNativeAnalysisPayload(),
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toResultJsonMtaSts(MtaStsNativeResult $native): array
    {
        $analysis = $this->analysisPayload->fromNative($native);

        return [
            'status' => $this->legacyStatus($native),
            'valid' => $native->protocolStatus === MtaStsProtocolStatus::VALID,
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
    public function toDnsRecordCompat(MtaStsNativeResult $native): array
    {
        if ($native->protocolStatus === MtaStsProtocolStatus::NONE) {
            return ['status' => 'missing', 'data' => null];
        }

        return [
            'status' => 'found',
            'data' => $native->rawIndicator,
        ];
    }

    private function legacyStatus(MtaStsNativeResult $native): string
    {
        return match ($native->state) {
            MtaStsStates::PASS => 'ok',
            MtaStsStates::WARNING => 'warning',
            MtaStsStates::FAIL, MtaStsStates::MISSING => 'error',
            default => 'unknown',
        };
    }
}
