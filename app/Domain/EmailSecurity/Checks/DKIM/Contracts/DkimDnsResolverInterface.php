<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Contracts;

use App\Domain\EmailSecurity\Checks\DKIM\Evaluation\DkimDnsQueryResult;

interface DkimDnsResolverInterface
{
    public function txt(string $hostname): DkimDnsQueryResult;

    public function reset(): void;
}
