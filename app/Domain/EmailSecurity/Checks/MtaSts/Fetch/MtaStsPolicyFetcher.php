<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Fetch;

use App\Domain\EmailSecurity\Checks\MtaSts\Contracts\MtaStsHttpClientInterface;

final class MtaStsPolicyFetcher
{
    public const MAX_BODY_BYTES = 65536;

    public function __construct(
        private MtaStsHttpClientInterface $httpClient,
    ) {
    }

    public function fetch(string $domain): MtaStsPolicyFetchResult
    {
        $domain = strtolower(rtrim(trim($domain), '.'));

        return $this->httpClient->fetchPolicy($domain);
    }

    public static function policyUrl(string $domain): string
    {
        return 'https://mta-sts.' . strtolower(rtrim(trim($domain), '.')) . '/.well-known/mta-sts.txt';
    }
}
