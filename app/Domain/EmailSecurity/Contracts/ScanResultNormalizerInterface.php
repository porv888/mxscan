<?php

namespace App\Domain\EmailSecurity\Contracts;

use App\Domain\EmailSecurity\DTO\NormalizedScanResultDTO;
use App\Domain\EmailSecurity\DTO\ScanResultDTO;

interface ScanResultNormalizerInterface
{
    public function normalize(ScanResultDTO $result): NormalizedScanResultDTO;
}
