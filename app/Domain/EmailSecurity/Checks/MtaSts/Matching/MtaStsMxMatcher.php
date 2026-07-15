<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Matching;

use App\Domain\EmailSecurity\Checks\MtaSts\Validation\MtaStsPolicyValidator;

final class MtaStsMxMatcher
{
    public function __construct(
        private MtaStsPolicyValidator $policyValidator,
    ) {
    }

    /**
     * @param list<array{hostname: string, priority: int, normalized_hostname: string}> $mxHosts
     * @param list<string> $patterns
     * @return list<MtaStsMxMatchResult>
     */
    public function match(array $mxHosts, array $patterns): array
    {
        $normalizedPatterns = array_map(
            fn (string $pattern) => $this->policyValidator->normalizeDomain($pattern),
            $patterns,
        );

        $results = [];
        foreach ($mxHosts as $mx) {
            $hostname = (string) ($mx['normalized_hostname'] ?? $mx['hostname'] ?? '');
            $priority = (int) ($mx['priority'] ?? 0);
            $match = $this->matchHost($hostname, $normalizedPatterns);

            $results[] = new MtaStsMxMatchResult(
                hostname: $hostname,
                priority: $priority,
                matchesPolicy: $match !== null,
                matchedPattern: $match,
                mismatchReason: $match === null ? 'Live MX host is not covered by the published MTA-STS policy.' : null,
            );
        }

        return $results;
    }

    /**
     * @param list<string> $patterns
     */
    private function matchHost(string $hostname, array $patterns): ?string
    {
        $hostname = $this->policyValidator->normalizeDomain($hostname);

        foreach ($patterns as $pattern) {
            if ($this->matchesPattern($hostname, $pattern)) {
                return $pattern;
            }
        }

        return null;
    }

    private function matchesPattern(string $hostname, string $pattern): bool
    {
        if (!str_contains($pattern, '*')) {
            return $hostname === $pattern;
        }

        if (!str_starts_with($pattern, '*.')) {
            return false;
        }

        $suffix = substr($pattern, 2);
        if ($hostname === $suffix) {
            return false;
        }

        if (!str_ends_with($hostname, '.' . $suffix)) {
            return false;
        }

        $prefix = substr($hostname, 0, -strlen('.' . $suffix));
        if ($prefix === '' || str_contains($prefix, '.')) {
            return false;
        }

        return true;
    }
}
