<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Contracts;

use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcDnsQueryResult;

interface DmarcDnsResolverInterface
{
    public function txt(string $hostname): DmarcDnsQueryResult;

    public function reset(): void;
}
