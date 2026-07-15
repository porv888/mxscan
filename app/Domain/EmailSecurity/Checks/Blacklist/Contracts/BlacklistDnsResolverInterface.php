<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist\Contracts;

use App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistDnsQueryResult;

interface BlacklistDnsResolverInterface
{
    public function queryA(string $queryHost, int $timeoutMs): BlacklistDnsQueryResult;
}
