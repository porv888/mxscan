<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Contracts;

use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiDnsQueryResult;

interface BimiDnsResolverInterface
{
    public function txt(string $hostname): BimiDnsQueryResult;

    public function cname(string $hostname): BimiDnsQueryResult;

    public function reset(): void;
}
