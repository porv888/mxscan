<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\MtaSts\Contracts\MtaStsHttpClientInterface;
use App\Domain\EmailSecurity\Checks\MtaSts\Fetch\MtaStsPolicyFetchResult;
use App\Domain\EmailSecurity\Checks\MtaSts\Fetch\MtaStsPolicyFetcher;

final class FakeMtaStsHttpClient implements MtaStsHttpClientInterface
{
    /** @var array<string, MtaStsPolicyFetchResult> */
    private array $responses = [];

    public function setResponse(string $domain, MtaStsPolicyFetchResult $result): void
    {
        $this->responses[strtolower($domain)] = $result;
    }

    public function fetchPolicy(string $domain): MtaStsPolicyFetchResult
    {
        $domain = strtolower(rtrim($domain, '.'));

        return $this->responses[$domain] ?? new MtaStsPolicyFetchResult(
            url: MtaStsPolicyFetcher::policyUrl($domain),
            status: MtaStsPolicyFetchResult::STATUS_HTTP_NON_200,
            httpStatus: 404,
            failureCategory: MtaStsPolicyFetchResult::STATUS_HTTP_NON_200,
        );
    }
}
