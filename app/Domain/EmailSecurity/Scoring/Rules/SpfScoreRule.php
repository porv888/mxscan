<?php

namespace App\Domain\EmailSecurity\Scoring\Rules;

use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;
use App\Domain\EmailSecurity\Checks\SPF\SpfProtocolStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy;
use App\Domain\EmailSecurity\DTO\ScoreComponentDTO;

final class SpfScoreRule
{
    public function score(SpfNativeResult $native): ScoreComponentDTO
    {
        $possible = (int) config('dns-scoring.spf.base', 20);
        $label = (string) config('dns-scoring.spf.label', 'SPF Record');

        if ($native->protocolStatus === SpfProtocolStatus::NONE) {
            return $this->component($label, $possible, 0, 'missing', $native->summary);
        }

        if ($native->protocolStatus === SpfProtocolStatus::PERMERROR) {
            return $this->component($label, $possible, 0, 'partial', $native->summary);
        }

        if ($native->protocolStatus === SpfProtocolStatus::TEMPERROR
            || $native->protocolStatus === SpfProtocolStatus::PARTIALLY_EVALUATED) {
            return $this->component($label, $possible, 8, 'partial', $native->summary);
        }

        if ($native->protocolStatus === SpfProtocolStatus::VALID) {
            $base = $this->terminalBase($native->terminalPolicy);
            if ($base === 8) {
                return $this->component($label, $possible, 8, 'partial', $native->summary);
            }

            $earned = $base;
            if ($earned > 0) {
                $earned -= $this->lookupDeduction($native->lookupCount);
                if ($this->hasDeprecatedPtr($native)) {
                    $earned -= 2;
                }
            }

            $earned = max(0, min($possible, $earned));
            $status = $earned === $possible ? 'ok' : 'partial';
            $reason = $this->reason($native, $earned, $base);

            return $this->component($label, $possible, $earned, $status, $reason);
        }

        return $this->component($label, $possible, 0, 'partial', $native->summary);
    }

    private function terminalBase(string $terminalPolicy): int
    {
        return match ($terminalPolicy) {
            SpfTerminalPolicy::HARD_FAIL => 20,
            SpfTerminalPolicy::SOFT_FAIL => 15,
            SpfTerminalPolicy::NEUTRAL, SpfTerminalPolicy::IMPLICIT_NEUTRAL => 10,
            SpfTerminalPolicy::PASS_ALL => 0,
            default => 8,
        };
    }

    private function lookupDeduction(int $lookupCount): int
    {
        if ($lookupCount >= 7 && $lookupCount <= 9) {
            return 2;
        }

        if ($lookupCount === 10) {
            return 4;
        }

        return 0;
    }

    private function hasDeprecatedPtr(SpfNativeResult $native): bool
    {
        foreach ($native->warnings as $warning) {
            if (($warning['code'] ?? '') === 'DEPRECATED_PTR') {
                return true;
            }
        }

        return false;
    }

    private function reason(SpfNativeResult $native, int $earned, int $base): ?string
    {
        if ($earned === $base && $native->summary !== '' && $native->riskStatus === 'healthy') {
            return null;
        }

        $parts = [];
        if ($native->summary !== '') {
            $parts[] = $native->summary;
        }

        $deduction = $base - $earned;
        if ($deduction > 0) {
            $parts[] = "Scoring deduction applied ({$deduction} point" . ($deduction === 1 ? '' : 's') . ').';
        }

        if ($parts === []) {
            return null;
        }

        return implode(' ', $parts);
    }

    private function component(
        string $label,
        int $possible,
        int $earned,
        string $status,
        ?string $reason,
    ): ScoreComponentDTO {
        return new ScoreComponentDTO(
            key: 'spf',
            label: $label,
            earned: $earned,
            possible: $possible,
            status: $status,
            reason: $reason,
            modelVersion: 'spf-v2',
        );
    }
}
