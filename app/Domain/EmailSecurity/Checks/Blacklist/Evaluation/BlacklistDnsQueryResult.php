<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist\Evaluation;

final class BlacklistDnsQueryResult
{
    /**
     * @param list<string> $addresses
     * @param list<string> $txtRecords
     */
    public function __construct(
        public readonly string $queryHost,
        public readonly bool $success,
        public readonly string $dnsOutcome,
        public readonly array $addresses = [],
        public readonly array $txtRecords = [],
        public readonly ?int $ttl = null,
        public readonly int $durationMs = 0,
        public readonly int $retryCount = 0,
        public readonly ?string $error = null,
        public readonly ?int $httpCode = null,
    ) {
    }
}
