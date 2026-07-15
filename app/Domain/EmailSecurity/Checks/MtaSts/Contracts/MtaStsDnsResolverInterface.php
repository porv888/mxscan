<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Contracts;

use App\Domain\EmailSecurity\Checks\MtaSts\Evaluation\MtaStsDnsQueryResult;

interface MtaStsDnsResolverInterface
{
    public function txt(string $hostname): MtaStsDnsQueryResult;

    public function cname(string $hostname): MtaStsDnsQueryResult;

    public function reset(): void;
}
