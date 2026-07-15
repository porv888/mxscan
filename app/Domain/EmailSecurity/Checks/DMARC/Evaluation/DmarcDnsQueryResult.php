<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Evaluation;

final class DmarcDnsQueryResult
{
    public const OUTCOME_SUCCESS = 'success';
    public const OUTCOME_EMPTY = 'empty';
    public const OUTCOME_NXDOMAIN = 'nxdomain';
    public const OUTCOME_TIMEOUT = 'timeout';
    public const OUTCOME_SERVFAIL = 'servfail';
    public const OUTCOME_ERROR = 'error';

    /**
     * @param list<array<string, mixed>> $rawRows
     * @param list<string> $reconstructedTxt
     */
    public function __construct(
        public readonly string $hostname,
        public readonly bool $success,
        public readonly array $rawRows = [],
        public readonly array $reconstructedTxt = [],
        public readonly ?string $error = null,
        public readonly ?int $ttl = null,
        public readonly string $outcome = self::OUTCOME_SUCCESS,
    ) {
    }

    public function failed(): bool
    {
        return !$this->success;
    }

    public function isTemperror(): bool
    {
        return in_array($this->outcome, [self::OUTCOME_TIMEOUT, self::OUTCOME_SERVFAIL, self::OUTCOME_ERROR], true);
    }
}
