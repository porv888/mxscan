<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist;

final class BlacklistQueryOutcome
{
    public const LISTED_ANSWER = 'listed_answer';
    public const CLEAN_NXDOMAIN = 'clean_nxdomain';
    public const CLEAN_NO_DATA = 'clean_no_data';
    public const TIMEOUT = 'timeout';
    public const SERVFAIL = 'servfail';
    public const REFUSED = 'refused';
    public const RATE_LIMITED = 'rate_limited';
    public const QUERY_BLOCKED = 'query_blocked';
    public const PROVIDER_ERROR = 'provider_error';
    public const MALFORMED_RESPONSE = 'malformed_response';
    public const UNSUPPORTED_TARGET = 'unsupported_target';
    public const SKIPPED = 'skipped';
    public const UNKNOWN_ANSWER = 'unknown_answer';

    /**
     * @return list<string>
     */
    public static function usableCleanOutcomes(): array
    {
        return [self::CLEAN_NXDOMAIN, self::CLEAN_NO_DATA];
    }

    /**
     * @return list<string>
     */
    public static function unavailableOutcomes(): array
    {
        return [
            self::TIMEOUT,
            self::SERVFAIL,
            self::REFUSED,
            self::RATE_LIMITED,
            self::QUERY_BLOCKED,
            self::PROVIDER_ERROR,
            self::MALFORMED_RESPONSE,
            self::UNKNOWN_ANSWER,
        ];
    }

    public static function isUsable(string $outcome): bool
    {
        return $outcome === self::LISTED_ANSWER
            || in_array($outcome, self::usableCleanOutcomes(), true);
    }

    public static function isClean(string $outcome): bool
    {
        return in_array($outcome, self::usableCleanOutcomes(), true);
    }

    public static function isListed(string $outcome): bool
    {
        return $outcome === self::LISTED_ANSWER;
    }
}
