<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Scoring;

use App\Domain\EmailSecurity\Checks\Bimi\BimiNativeResult;
use App\Domain\EmailSecurity\DTO\ScoreComponentDTO;

final class BimiScoreRule
{
    public function score(BimiNativeResult $native): ScoreComponentDTO
    {
        $possible = (int) config('dns-scoring.bimi.valid', 0);
        $label = (string) config('dns-scoring.bimi.label', 'BIMI');

        return new ScoreComponentDTO(
            key: 'bimi',
            label: $label,
            earned: 0,
            possible: $possible,
            status: 'not_scored',
            reason: $native->summary,
            modelVersion: 'bimi-readiness-v1',
        );
    }
}
