<?php

namespace App\Domain\EmailSecurity\Contracts;

use App\Domain\EmailSecurity\DTO\RecommendationListDTO;
use App\Domain\EmailSecurity\DTO\ScanResultDTO;
use App\Models\Domain;

interface RecommendationEngineInterface
{
    public function build(Domain $domain, ScanResultDTO $scanResult): RecommendationListDTO;
}
