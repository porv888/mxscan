<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Evaluation;

final class SpfDnsQueryResult
{
    /**
     * @param list<string> $records
     */
    public function __construct(
        public readonly string $host,
        public readonly string $type,
        public readonly bool $success,
        public readonly array $records = [],
        public readonly ?string $error = null,
        public readonly ?int $ttl = null,
        public readonly bool $nxdomain = false,
        public readonly bool $empty = false,
    ) {
    }

    public function failed(): bool
    {
        return !$this->success;
    }
}
