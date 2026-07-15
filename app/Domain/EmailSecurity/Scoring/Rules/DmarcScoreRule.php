<?php

namespace App\Domain\EmailSecurity\Scoring\Rules;

use App\Domain\EmailSecurity\Checks\DMARC\DmarcNativeResult;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcProtocolStatus;
use App\Domain\EmailSecurity\DTO\ScoreComponentDTO;

final class DmarcScoreRule
{
    public function score(DmarcNativeResult $native): ScoreComponentDTO
    {
        $possible = (int) config('dns-scoring.dmarc.base', 30);
        $label = (string) config('dns-scoring.dmarc.label', 'DMARC');

        if ($native->protocolStatus === DmarcProtocolStatus::NONE
            || $native->protocolStatus === DmarcProtocolStatus::PERMERROR) {
            return $this->component($label, $possible, 0, 'missing', $native->summary);
        }

        if ($native->protocolStatus === DmarcProtocolStatus::TEMPERROR
            || $native->protocolStatus === DmarcProtocolStatus::PARTIALLY_EVALUATED) {
            return $this->component($label, $possible, 8, 'partial', $native->summary);
        }

        if ($native->protocolStatus === DmarcProtocolStatus::VALID) {
            $earned = $this->enforcementScore($native);
            $status = $earned === $possible ? 'ok' : ($earned === 0 ? 'missing' : 'partial');

            return $this->component($label, $possible, $earned, $status, $native->summary);
        }

        return $this->component($label, $possible, 0, 'partial', $native->summary);
    }

    private function enforcementScore(DmarcNativeResult $native): int
    {
        $policy = $native->policy;
        $enforcement = $policy['enforcement'] ?? 'unknown';
        $effectivePolicy = $policy['effective_policy'] ?? null;
        $pct = (int) ($policy['pct'] ?? 100);
        $testingMode = (bool) ($policy['testing_mode'] ?? false);

        if ($testingMode || $effectivePolicy === 'none' || $pct === 0) {
            return 12;
        }

        return match ($enforcement) {
            'monitoring' => 12,
            'partial_enforcement' => $effectivePolicy === 'reject' ? 27 : 20,
            'quarantine' => 24,
            'reject' => 30,
            default => 0,
        };
    }

    private function component(
        string $label,
        int $possible,
        int $earned,
        string $status,
        ?string $reason,
    ): ScoreComponentDTO {
        return new ScoreComponentDTO(
            key: 'dmarc',
            label: $label,
            earned: $earned,
            possible: $possible,
            status: $status,
            reason: $reason,
            modelVersion: 'dmarc-v1',
        );
    }
}
