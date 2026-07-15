<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Compatibility;

use App\Domain\EmailSecurity\Checks\DKIM\DkimNativeResult;
use App\Domain\EmailSecurity\Checks\DKIM\DkimProtocolStatus;
use App\Domain\EmailSecurity\Checks\DKIM\DkimStates;

final class DkimLegacyPayloadAdapter
{
    public function __construct(
        private DkimNativeAnalysisPayload $analysisPayload = new DkimNativeAnalysisPayload(),
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toResultJsonDkim(DkimNativeResult $native): array
    {
        $analysis = $this->analysisPayload->fromNative($native);

        return [
            'status' => $this->legacyStatus($native),
            'valid' => $native->protocolStatus === DkimProtocolStatus::VALID,
            'protocol_status' => $analysis['protocol_status'],
            'risk_status' => $analysis['risk_status'],
            'ui_state' => $analysis['state'],
            'summary' => $analysis['summary'],
            'analysis' => $analysis,
        ];
    }

    /**
     * @return array{status: string, data: list<array<string, mixed>>}
     */
    public function toDnsRecordCompat(DkimNativeResult $native): array
    {
        $data = [];

        foreach ($native->selectors as $selector) {
            if (($selector['record_status'] ?? '') === 'valid') {
                $data[] = [
                    'selector' => $selector['selector'],
                    'record' => $this->recordPreview($selector),
                    'key_type' => $selector['key_type'] ?? null,
                    'key_bits' => $selector['key_bits'] ?? null,
                ];
            }
        }

        if ($data === []) {
            return ['status' => 'missing', 'data' => []];
        }

        return ['status' => 'found', 'data' => $data];
    }

    private function legacyStatus(DkimNativeResult $native): string
    {
        return match ($native->state) {
            DkimStates::PASS => 'ok',
            DkimStates::WARNING => 'warning',
            DkimStates::FAIL, DkimStates::MISSING => 'error',
            default => 'unknown',
        };
    }

    /**
     * @param array<string, mixed> $selector
     */
    private function recordPreview(array $selector): string
    {
        $type = $selector['key_type'] ?? 'unknown';
        $bits = $selector['key_bits'] ?? null;

        if ($bits !== null) {
            return "v=DKIM1; k={$type}; p=[{$bits}-bit public key]";
        }

        return "v=DKIM1; k={$type}; p=[public key]";
    }
}
