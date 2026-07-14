<?php

namespace App\Domain\EmailSecurity\Contracts;

use App\Domain\EmailSecurity\DTO\ScanReportViewModelDTO;
use App\Models\Domain;
use App\Models\Scan;

interface ScanReportFactoryInterface
{
    public function build(Scan $scan, Domain $domain): ScanReportViewModelDTO;
}
