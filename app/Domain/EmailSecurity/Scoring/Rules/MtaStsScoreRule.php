<?php

namespace App\Domain\EmailSecurity\Scoring\Rules;

use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsNativeResult;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsProtocolStatus;
use App\Domain\EmailSecurity\Checks\MtaSts\Validation\MtaStsPolicyValidationResult;
use App\Domain\EmailSecurity\DTO\ScoreComponentDTO;

final class MtaStsScoreRule
{
    public function score(MtaStsNativeResult $native): ScoreComponentDTO
    {
        $possible = (int) config('dns-scoring.mtasts.max', 10);
        $label = (string) config('dns-scoring.mtasts.label', 'MTA-STS');

        if (in_array($native->protocolStatus, [
            MtaStsProtocolStatus::TEMPERROR,
            MtaStsProtocolStatus::PARTIALLY_EVALUATED,
        ], true)) {
            return $this->component($label, $possible, 3, 'partial', $native->summary);
        }

        if ($this->scoresZero($native)) {
            return $this->component($label, $possible, 0, 'missing', $native->summary);
        }

        $mode = $native->policy['mode'] ?? null;

        if ($mode === 'none') {
            return $this->component($label, $possible, 4, 'partial', $native->summary);
        }

        if ($mode === 'testing') {
            return $this->component($label, $possible, 7, 'partial', $native->summary);
        }

        if ($mode === 'enforce') {
            $earned = $this->enforceScore($native);

            return $this->component(
                $label,
                $possible,
                $earned,
                $earned === $possible ? 'ok' : 'partial',
                $native->summary,
            );
        }

        return $this->component($label, $possible, 0, 'missing', $native->summary);
    }

    private function scoresZero(MtaStsNativeResult $native): bool
    {
        if (in_array($native->protocolStatus, [MtaStsProtocolStatus::NONE, MtaStsProtocolStatus::PERMERROR], true)) {
            return true;
        }

        if (($native->policyHostTls['valid'] ?? true) === false) {
            return true;
        }

        if (($native->policy['mode'] ?? null) === 'enforce') {
            foreach ($native->mxValidation as $mx) {
                if (($mx['matches_policy'] ?? false) === false) {
                    return true;
                }

                if ($this->isDefinitivelyInvalidSmtpCert($mx)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function enforceScore(MtaStsNativeResult $native): int
    {
        if ($this->hasOperationalWarnings($native)) {
            return 8;
        }

        return 10;
    }

    private function hasOperationalWarnings(MtaStsNativeResult $native): bool
    {
        $maxAge = $native->policy['max_age'] ?? null;
        if (is_int($maxAge) && $maxAge < MtaStsPolicyValidationResult::OPERATIONAL_SHORT_MAX_AGE) {
            return true;
        }

        foreach ($native->mxValidation as $mx) {
            if (($mx['starttls'] ?? null) === false) {
                return true;
            }

            if (($mx['smtp_tls']['inspection_status'] ?? null) === 'timeout') {
                return true;
            }

            if (($mx['certificate_valid'] ?? null) === false && !$this->isDefinitivelyInvalidSmtpCert($mx)) {
                return true;
            }
        }

        foreach ($native->warnings as $warning) {
            if (($warning['code'] ?? '') === 'UNEXPECTED_CONTENT_TYPE') {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, mixed> $mx
     */
    private function isDefinitivelyInvalidSmtpCert(array $mx): bool
    {
        $smtp = is_array($mx['smtp_tls'] ?? null) ? $mx['smtp_tls'] : [];

        return ($smtp['tls_negotiation_success'] ?? false) === true
            && (
                ($mx['certificate_valid'] ?? false) === false
                || ($mx['hostname_match'] ?? false) === false
            );
    }

    private function component(string $label, int $possible, int $earned, string $status, ?string $reason): ScoreComponentDTO
    {
        return new ScoreComponentDTO(
            key: 'mtasts',
            label: $label,
            earned: $earned,
            possible: $possible,
            status: $status,
            reason: $reason,
            modelVersion: 'mta-sts-v1',
        );
    }
}
