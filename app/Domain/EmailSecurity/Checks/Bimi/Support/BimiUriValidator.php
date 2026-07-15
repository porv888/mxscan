<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Support;

use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxAddressClassifier;

final class BimiUriValidator
{
    public function __construct(
        private MxAddressClassifier $addressClassifier,
    ) {
    }

    /**
     * @return array{
     *     valid: bool,
     *     normalized_uri: ?string,
     *     host: ?string,
     *     errors: list<array{code: string, message: string}>
     * }
     */
    public function validate(string $uri): array
    {
        $uri = trim($uri);
        $errors = [];

        if ($uri === '') {
            return [
                'valid' => false,
                'normalized_uri' => null,
                'host' => null,
                'errors' => [[
                    'code' => 'EMPTY_URI',
                    'message' => 'URI must not be empty.',
                ]],
            ];
        }

        $parts = parse_url($uri);
        if (!is_array($parts)) {
            return $this->invalid('MALFORMED_URI', 'URI is malformed.', $errors);
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        if ($scheme !== 'https') {
            $errors[] = [
                'code' => 'NON_HTTPS_SCHEME',
                'message' => 'BIMI URIs must use HTTPS.',
            ];
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            $errors[] = [
                'code' => 'URI_CREDENTIALS_FORBIDDEN',
                'message' => 'BIMI URIs must not contain credentials.',
            ];
        }

        $host = $parts['host'] ?? null;
        if (!is_string($host) || $host === '') {
            $errors[] = [
                'code' => 'MISSING_HOST',
                'message' => 'URI host is required.',
            ];
        }

        $port = $parts['port'] ?? null;
        $allowedPort = (int) config('bimi.fetch.allowed_port', 443);
        if ($port !== null && (int) $port !== $allowedPort) {
            $errors[] = [
                'code' => 'INVALID_PORT',
                'message' => 'BIMI URIs must use port ' . $allowedPort . '.',
            ];
        }

        if ($host !== null && $host !== '') {
            $host = strtolower(rtrim($host, '.'));
            if (str_contains($host, '..') || str_starts_with($host, '-') || str_ends_with($host, '-')) {
                $errors[] = [
                    'code' => 'INVALID_HOST',
                    'message' => 'URI host is invalid.',
                ];
            }

            $resolved = $this->resolveHostSafety($host);
            if (!$resolved['safe']) {
                $errors[] = [
                    'code' => 'SSRF_BLOCKED',
                    'message' => $resolved['message'],
                ];
            }
        }

        $normalized = null;
        if ($errors === [] && is_string($host) && $host !== '') {
            $normalized = 'https://' . $host;
            if ($port !== null && (int) $port !== 443) {
                $normalized .= ':' . $port;
            }
            $normalized .= $parts['path'] ?? '';
            if (isset($parts['query']) && $parts['query'] !== '') {
                $normalized .= '?' . $parts['query'];
            }
        }

        return [
            'valid' => $errors === [],
            'normalized_uri' => $normalized,
            'host' => is_string($host) ? $host : null,
            'errors' => $errors,
        ];
    }

    /**
     * @param list<array{code: string, message: string}> $errors
     * @return array{valid: bool, normalized_uri: null, host: null, errors: list<array{code: string, message: string}>}
     */
    private function invalid(string $code, string $message, array $errors): array
    {
        $errors[] = ['code' => $code, 'message' => $message];

        return [
            'valid' => false,
            'normalized_uri' => null,
            'host' => null,
            'errors' => $errors,
        ];
    }

    /**
     * @return array{safe: bool, message: string, resolved_ips: list<string>}
     */
    public function resolveHostSafety(string $host): array
    {
        $host = strtolower(rtrim(trim($host), '.'));
        $resolvedIps = [];

        $aRecords = @dns_get_record($host, DNS_A);
        if (is_array($aRecords)) {
            foreach ($aRecords as $row) {
                if (isset($row['ip']) && is_string($row['ip'])) {
                    $resolvedIps[] = $row['ip'];
                }
            }
        }

        $aaaaRecords = @dns_get_record($host, DNS_AAAA);
        if (is_array($aaaaRecords)) {
            foreach ($aaaaRecords as $row) {
                if (isset($row['ipv6']) && is_string($row['ipv6'])) {
                    $resolvedIps[] = $row['ipv6'];
                }
            }
        }

        if ($resolvedIps === []) {
            return [
                'safe' => true,
                'message' => '',
                'resolved_ips' => [],
            ];
        }

        foreach ($resolvedIps as $ip) {
            $classification = $this->addressClassifier->classify($ip);
            if (!$classification['usable']) {
                return [
                    'safe' => false,
                    'message' => 'URI resolves to a non-public destination (' . $classification['classification'] . ').',
                    'resolved_ips' => $resolvedIps,
                ];
            }
        }

        return [
            'safe' => true,
            'message' => '',
            'resolved_ips' => $resolvedIps,
        ];
    }
}
