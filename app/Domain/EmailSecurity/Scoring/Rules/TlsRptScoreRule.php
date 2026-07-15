<?php

namespace App\Domain\EmailSecurity\Scoring\Rules;

use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptNativeResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptProtocolStatus;
use App\Domain\EmailSecurity\DTO\ScoreComponentDTO;

final class TlsRptScoreRule
{
    public function score(TlsRptNativeResult $native): ScoreComponentDTO
    {
        $possible = (int) config('dns-scoring.tlsrpt.max', 5);
        $label = (string) config('dns-scoring.tlsrpt.label', 'TLS-RPT');

        if ($native->protocolStatus === TlsRptProtocolStatus::TEMPERROR) {
            return $this->component($label, $possible, 2, 'partial', $native->summary);
        }

        if ($this->scoresZero($native)) {
            return $this->component($label, $possible, 0, 'missing', $native->summary);
        }

        if ($native->hasMaterialWarnings || $native->state === 'warning') {
            return $this->component($label, $possible, 4, 'partial', $native->summary);
        }

        return $this->component($label, $possible, 5, 'ok', $native->summary);
    }

    private function scoresZero(TlsRptNativeResult $native): bool
    {
        return in_array($native->protocolStatus, [
            TlsRptProtocolStatus::NONE,
            TlsRptProtocolStatus::PERMERROR,
        ], true);
    }

    private function component(string $label, int $possible, int $earned, string $status, ?string $reason): ScoreComponentDTO
    {
        return new ScoreComponentDTO(
            key: 'tlsrpt',
            label: $label,
            earned: $earned,
            possible: $possible,
            status: $status,
            reason: $reason,
            modelVersion: 'tls-rpt-v1',
        );
    }
}
