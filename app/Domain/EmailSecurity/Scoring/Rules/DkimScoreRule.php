<?php

namespace App\Domain\EmailSecurity\Scoring\Rules;

use App\Domain\EmailSecurity\Checks\DKIM\DkimNativeResult;
use App\Domain\EmailSecurity\Checks\DKIM\DkimProtocolStatus;
use App\Domain\EmailSecurity\Checks\DKIM\DkimSelectorSource;
use App\Domain\EmailSecurity\DTO\ScoreComponentDTO;

final class DkimScoreRule
{
    public function score(DkimNativeResult $native): ScoreComponentDTO
    {
        $possible = (int) config('dns-scoring.dkim.max', 20);
        $label = (string) config('dns-scoring.dkim.label', 'DKIM DNS configuration');

        if ($native->protocolStatus === DkimProtocolStatus::PARTIALLY_EVALUATED) {
            return $this->component($label, $possible, 8, 'partial', $native->summary);
        }

        if ($native->protocolStatus === DkimProtocolStatus::TEMPERROR) {
            return $this->component($label, $possible, 8, 'partial', $native->summary);
        }

        if ($this->hasAuthoritativeFailure($native)) {
            return $this->component($label, $possible, 0, 'missing', $native->summary);
        }

        if ($native->protocolStatus === DkimProtocolStatus::NONE) {
            $coverage = $native->selectorCoverage['coverage_type'] ?? 'catalog_only';
            $earned = $coverage === 'catalog_only' ? 10 : 0;

            return $this->component($label, $possible, $earned, $earned > 0 ? 'partial' : 'missing', $native->summary);
        }

        if ($native->protocolStatus === DkimProtocolStatus::VALID) {
            return $this->component($label, $possible, $this->validKeyScore($native), $this->validStatus($native), $native->summary);
        }

        return $this->component($label, $possible, 0, 'partial', $native->summary);
    }

    private function hasAuthoritativeFailure(DkimNativeResult $native): bool
    {
        foreach ($native->selectors as $selector) {
            if (!DkimSelectorSource::isAuthoritative($selector['source'] ?? '')) {
                continue;
            }

            $status = $selector['record_status'] ?? '';
            if (in_array($status, ['invalid', 'revoked', 'ambiguous', 'unsupported'], true)) {
                return true;
            }

            if (($selector['protocol_status'] ?? '') === DkimProtocolStatus::PERMERROR) {
                return true;
            }
        }

        return $native->protocolStatus === DkimProtocolStatus::PERMERROR
            || $native->protocolStatus === DkimProtocolStatus::REVOKED;
    }

    private function validKeyScore(DkimNativeResult $native): int
    {
        $best = 0;

        foreach ($native->selectors as $selector) {
            if (($selector['record_status'] ?? '') !== 'valid') {
                continue;
            }

            $score = $this->selectorScore($selector, $native);
            $best = max($best, $score);
        }

        return $best;
    }

    /**
     * @param array<string, mixed> $selector
     */
    private function selectorScore(array $selector, DkimNativeResult $native): int
    {
        $type = $selector['key_type'] ?? null;
        $bits = $selector['key_bits'] ?? null;
        $testing = (bool) ($selector['testing'] ?? false);
        $warnings = count($selector['warnings'] ?? []);

        if ($type === 'ed25519') {
            return $testing ? 18 : 20;
        }

        if ($type === 'rsa') {
            if ($bits !== null && $bits >= 2048) {
                return $testing ? 18 : 20;
            }
            if ($bits !== null && $bits >= 1024) {
                return $warnings > 1 ? 15 : 15;
            }
        }

        if ($testing || $warnings > 0) {
            return 10;
        }

        return 15;
    }

    private function validStatus(DkimNativeResult $native): string
    {
        $earned = $this->validKeyScore($native);
        $possible = (int) config('dns-scoring.dkim.max', 20);

        return $earned === $possible ? 'ok' : 'partial';
    }

    private function component(string $label, int $possible, int $earned, string $status, ?string $reason): ScoreComponentDTO
    {
        return new ScoreComponentDTO(
            key: 'dkim',
            label: $label,
            earned: $earned,
            possible: $possible,
            status: $status,
            reason: $reason,
            modelVersion: 'dkim-v1',
        );
    }
}
