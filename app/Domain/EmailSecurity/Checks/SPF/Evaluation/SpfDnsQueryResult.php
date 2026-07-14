<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Evaluation;

final class SpfDnsQueryResult
{
    public const OUTCOME_SUCCESS = 'success';
    public const OUTCOME_EMPTY = 'empty';
    public const OUTCOME_NXDOMAIN = 'nxdomain';
    public const OUTCOME_TIMEOUT = 'timeout';
    public const OUTCOME_SERVFAIL = 'servfail';
    public const OUTCOME_ERROR = 'error';

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
        public readonly string $outcome = self::OUTCOME_SUCCESS,
    ) {
    }

    public function failed(): bool
    {
        return !$this->success;
    }

    public function isVoidEligible(): bool
    {
        return in_array($this->outcome, [self::OUTCOME_EMPTY, self::OUTCOME_NXDOMAIN], true);
    }

    public function isTemperror(): bool
    {
        return in_array($this->outcome, [self::OUTCOME_TIMEOUT, self::OUTCOME_SERVFAIL, self::OUTCOME_ERROR], true);
    }
}
