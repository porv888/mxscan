<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Evaluation;

final class MxDnsQueryResult
{
    public const OUTCOME_ANSWER = 'answer';
    public const OUTCOME_NO_DATA = 'no_data';
    public const OUTCOME_NXDOMAIN = 'nxdomain';
    public const OUTCOME_TIMEOUT = 'timeout';
    public const OUTCOME_SERVFAIL = 'servfail';
    public const OUTCOME_REFUSED = 'refused';
    public const OUTCOME_MALFORMED = 'malformed_response';
    public const OUTCOME_ERROR = 'error';

    /**
     * @param list<array<string, mixed>> $rawRows
     * @param list<string> $addresses
     * @param list<string> $cnameTargets
     */
    public function __construct(
        public readonly string $hostname,
        public readonly bool $success,
        public readonly array $rawRows = [],
        public readonly array $addresses = [],
        public readonly array $cnameTargets = [],
        public readonly ?string $error = null,
        public readonly ?int $ttl = null,
        public readonly string $outcome = self::OUTCOME_ANSWER,
    ) {
    }

    public function failed(): bool
    {
        return !$this->success;
    }

    public function isTemperror(): bool
    {
        return in_array($this->outcome, [
            self::OUTCOME_TIMEOUT,
            self::OUTCOME_SERVFAIL,
            self::OUTCOME_REFUSED,
            self::OUTCOME_ERROR,
        ], true);
    }

    public function isGenuinelyAbsent(): bool
    {
        return $this->outcome === self::OUTCOME_NO_DATA;
    }
}
