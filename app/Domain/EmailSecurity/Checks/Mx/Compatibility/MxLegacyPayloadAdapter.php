<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Compatibility;

use App\Domain\EmailSecurity\Checks\Mx\MxNativeResult;
use App\Domain\EmailSecurity\Checks\Mx\MxProtocolStatus;
use App\Domain\EmailSecurity\Checks\Mx\MxStates;

final class MxLegacyPayloadAdapter
{
    public function __construct(
        private MxNativeAnalysisPayload $analysisPayload = new MxNativeAnalysisPayload(),
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toResultJsonMx(MxNativeResult $native): array
    {
        $analysis = $this->analysisPayload->fromNative($native);

        return [
            'status' => $this->legacyStatus($native),
            'protocol_status' => $analysis['protocol_status'],
            'risk_status' => $analysis['risk_status'],
            'ui_state' => $analysis['state'],
            'summary' => $analysis['summary'],
            'analysis' => $analysis,
        ];
    }

    /**
     * @return array{status: string, data: ?array<int, array<string, mixed>>}
     */
    public function toDnsRecordCompat(MxNativeResult $native): array
    {
        if ($native->protocolStatus === MxProtocolStatus::NONE) {
            return ['status' => 'missing', 'data' => null];
        }

        if ($native->protocolStatus === MxProtocolStatus::TEMPERROR) {
            return ['status' => 'unknown', 'data' => null];
        }

        if (($native->nullMx['valid'] ?? false) === true) {
            return [
                'status' => 'found',
                'data' => [['pri' => 0, 'target' => '.']],
            ];
        }

        if ($native->protocolStatus === MxProtocolStatus::VALID
            && $native->serviceMode === \App\Domain\EmailSecurity\Checks\Mx\MxServiceMode::IMPLICIT_DELIVERY) {
            return ['status' => 'missing', 'data' => null];
        }

        $data = [];
        foreach ($native->targets as $target) {
            $data[] = [
                'pri' => $target['preference'] ?? 0,
                'target' => $target['hostname'] ?? $target['normalized_hostname'] ?? '',
            ];
        }

        if ($data === [] && $native->recordsTotal > 0) {
            return ['status' => 'partial', 'data' => null];
        }

        return [
            'status' => $data === [] ? 'missing' : 'found',
            'data' => $data === [] ? null : $data,
        ];
    }

    private function legacyStatus(MxNativeResult $native): string
    {
        return match ($native->state) {
            MxStates::PASS => 'ok',
            MxStates::WARNING => 'warning',
            MxStates::FAIL, MxStates::MISSING => 'error',
            default => 'unknown',
        };
    }
}
