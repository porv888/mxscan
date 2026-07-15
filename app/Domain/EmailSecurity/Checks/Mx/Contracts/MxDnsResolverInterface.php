<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Contracts;

use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxDnsQueryResult;

interface MxDnsResolverInterface
{
    public function mx(string $domain): MxDnsQueryResult;

    public function a(string $hostname): MxDnsQueryResult;

    public function aaaa(string $hostname): MxDnsQueryResult;

    public function cname(string $hostname): MxDnsQueryResult;
}
