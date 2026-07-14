<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Parsing;

final class SpfParser
{
    private const QUALIFIERS = ['+', '-', '~', '?'];

    /**
     * @return list<SpfParsedTerm>
     */
    public function parse(string $record, string $sourceDomain): array
    {
        $normalized = preg_replace('/\s+/', ' ', trim($record)) ?? '';
        $tokens = explode(' ', $normalized);
        $terms = [];
        $position = 0;

        foreach ($tokens as $token) {
            $token = trim($token);
            if ($token === '' || strcasecmp($token, 'v=spf1') === 0) {
                continue;
            }

            $terms[] = $this->parseToken($token, $position++, $sourceDomain);
        }

        return $terms;
    }

    private function parseToken(string $token, int $position, string $sourceDomain): SpfParsedTerm
    {
        $qualifier = '+';
        $body = $token;

        if ($body !== '' && in_array($body[0], self::QUALIFIERS, true)) {
            $qualifier = $body[0];
            $body = substr($body, 1);
        }

        if (str_starts_with($body, 'redirect=')) {
            return new SpfParsedTerm(
                position: $position,
                raw: $token,
                qualifier: $qualifier,
                type: 'modifier',
                name: 'redirect',
                argument: substr($body, 9) !== '' ? substr($body, 9) : null,
                sourceDomain: $sourceDomain,
            );
        }

        if (str_starts_with($body, 'exp=')) {
            return new SpfParsedTerm(
                position: $position,
                raw: $token,
                qualifier: $qualifier,
                type: 'modifier',
                name: 'exp',
                argument: substr($body, 4) !== '' ? substr($body, 4) : null,
                sourceDomain: $sourceDomain,
            );
        }

        if (preg_match('/^(?<name>all|include|a|mx|ip4|ip6|ptr|exists)(?::(?<arg>.*))?$/', $body, $matches)) {
            $name = $matches['name'];
            $argument = $matches['arg'] ?? null;
            $cidrV4 = null;
            $cidrV6 = null;

            if ($argument !== null && str_contains($argument, '/')) {
                [$argument, $cidr] = explode('/', $argument, 2);
                if ($name === 'ip4' || $name === 'a') {
                    $cidrV4 = is_numeric($cidr) ? (int) $cidr : null;
                } elseif ($name === 'ip6') {
                    $cidrV6 = is_numeric($cidr) ? (int) $cidr : null;
                }
            }

            return new SpfParsedTerm(
                position: $position,
                raw: $token,
                qualifier: $qualifier,
                type: 'mechanism',
                name: $name,
                argument: $argument !== '' ? $argument : null,
                cidrV4: $cidrV4,
                cidrV6: $cidrV6,
                sourceDomain: $sourceDomain,
            );
        }

        return new SpfParsedTerm(
            position: $position,
            raw: $token,
            qualifier: $qualifier,
            type: 'mechanism',
            name: 'unknown',
            argument: $body !== '' ? $body : null,
            sourceDomain: $sourceDomain,
            errors: [['code' => 'UNKNOWN_MECHANISM', 'message' => "Unknown SPF term: {$token}"]],
        );
    }
}
