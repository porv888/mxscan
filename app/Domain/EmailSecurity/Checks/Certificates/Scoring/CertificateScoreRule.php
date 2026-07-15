<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Scoring;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateNativeResult;
use App\Domain\EmailSecurity\DTO\ScoreComponentDTO;

final class CertificateScoreRule
{
    public function score(CertificateNativeResult $native): ScoreComponentDTO
    {
        return new ScoreComponentDTO(
            key: 'certificates',
            label: 'Certificates',
            earned: 0,
            possible: 0,
            status: 'not_scored',
            reason: $native->summary,
            modelVersion: 'certificates-v1',
        );
    }
}
