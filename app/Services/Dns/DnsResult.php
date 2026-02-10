<?php

namespace App\Services\Dns;

class DnsResult
{
    public function __construct(
        public readonly array $records,
        public readonly bool $success,
        public readonly ?string $error = null,
    ) {}

    /**
     * Whether the DNS lookup failed (network error, timeout, etc.)
     */
    public function failed(): bool
    {
        return !$this->success;
    }

    /**
     * Whether the lookup succeeded but returned no records.
     */
    public function isEmpty(): bool
    {
        return $this->success && empty($this->records);
    }

    /**
     * Whether the lookup succeeded and returned records.
     */
    public function hasRecords(): bool
    {
        return $this->success && !empty($this->records);
    }
}
