<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Contracts;

use App\Domain\EmailSecurity\Checks\TlsRpt\Evaluation\TlsRptDnsQueryResult;

interface TlsRptDnsResolverInterface
{
    public function txt(string $hostname): TlsRptDnsQueryResult;

    public function cname(string $hostname): TlsRptDnsQueryResult;

    public function reset(): void;
}
