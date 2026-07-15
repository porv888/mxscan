<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Contracts;

use App\Domain\EmailSecurity\Checks\MtaSts\Fetch\MtaStsPolicyFetchResult;

interface MtaStsHttpClientInterface
{
    public function fetchPolicy(string $domain): MtaStsPolicyFetchResult;
}
