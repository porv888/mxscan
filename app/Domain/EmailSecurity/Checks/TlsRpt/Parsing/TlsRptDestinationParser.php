<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Parsing;

final class TlsRptDestinationParser
{
    /**
     * @return list<TlsRptParsedDestination>
     */
    public function parseList(string $ruaValue): array
    {
        $destinations = [];

        foreach ($this->splitDestinations($ruaValue) as $rawUri) {
            $destinations[] = $this->parseOne($rawUri);
        }

        return $destinations;
    }

    /**
     * @return list<string>
     */
    private function splitDestinations(string $value): array
    {
        $uris = [];
        foreach (preg_split('/\s*,\s*/', trim($value)) ?: [] as $chunk) {
            $chunk = trim($chunk);
            if ($chunk !== '') {
                $uris[] = $chunk;
            }
        }

        return $uris;
    }

    public function parseOne(string $rawUri): TlsRptParsedDestination
    {
        $rawUri = trim($rawUri);
        if ($rawUri === '') {
            return new TlsRptParsedDestination(
                rawUri: $rawUri,
                normalizedUri: null,
                scheme: null,
                addressOrHost: null,
                status: TlsRptParsedDestination::STATUS_EMPTY,
                errors: [[
                    'code' => 'EMPTY_DESTINATION',
                    'message' => 'Empty reporting destination entry.',
                ]],
            );
        }

        if (preg_match('/^mailto:\s*(.+)$/i', $rawUri, $matches)) {
            return $this->parseMailto($rawUri, trim($matches[1]));
        }

        if (preg_match('/^https:\/\//i', $rawUri)) {
            return $this->parseHttps($rawUri);
        }

        if (preg_match('/^http:\/\//i', $rawUri)) {
            return new TlsRptParsedDestination(
                rawUri: $rawUri,
                normalizedUri: null,
                scheme: 'http',
                addressOrHost: null,
                status: TlsRptParsedDestination::STATUS_INVALID,
                errors: [[
                    'code' => 'HTTP_SCHEME_REJECTED',
                    'message' => 'Plain HTTP reporting destinations are not permitted; use HTTPS.',
                ]],
            );
        }

        $scheme = strtolower((string) (parse_url($rawUri, PHP_URL_SCHEME) ?? ''));

        return new TlsRptParsedDestination(
            rawUri: $rawUri,
            normalizedUri: null,
            scheme: $scheme !== '' ? $scheme : null,
            addressOrHost: null,
            status: TlsRptParsedDestination::STATUS_UNSUPPORTED_SCHEME,
            errors: [[
                'code' => 'UNSUPPORTED_SCHEME',
                'message' => 'Unsupported TLS-RPT reporting URI scheme.',
            ]],
        );
    }

    private function parseMailto(string $rawUri, string $target): TlsRptParsedDestination
    {
        $email = strtolower(trim($target));
        if ($email === '' || !str_contains($email, '@')) {
            return new TlsRptParsedDestination(
                rawUri: $rawUri,
                normalizedUri: null,
                scheme: 'mailto',
                addressOrHost: null,
                status: TlsRptParsedDestination::STATUS_INVALID,
                errors: [[
                    'code' => 'MALFORMED_MAILTO',
                    'message' => 'Malformed mailto reporting destination.',
                ]],
            );
        }

        if (!preg_match('/^[^\s@]+@[^\s@]+\.[^\s@]+$/', $email)) {
            return new TlsRptParsedDestination(
                rawUri: $rawUri,
                normalizedUri: null,
                scheme: 'mailto',
                addressOrHost: $email,
                status: TlsRptParsedDestination::STATUS_INVALID,
                errors: [[
                    'code' => 'MALFORMED_MAILTO',
                    'message' => 'Malformed mailto reporting destination.',
                ]],
            );
        }

        $normalized = 'mailto:' . $email;

        return new TlsRptParsedDestination(
            rawUri: $rawUri,
            normalizedUri: $normalized,
            scheme: 'mailto',
            addressOrHost: $email,
            status: TlsRptParsedDestination::STATUS_VALID,
        );
    }

    private function parseHttps(string $rawUri): TlsRptParsedDestination
    {
        $parts = parse_url($rawUri);
        if ($parts === false || !isset($parts['host']) || $parts['host'] === '') {
            return new TlsRptParsedDestination(
                rawUri: $rawUri,
                normalizedUri: null,
                scheme: 'https',
                addressOrHost: null,
                status: TlsRptParsedDestination::STATUS_INVALID,
                errors: [[
                    'code' => 'MALFORMED_HTTPS',
                    'message' => 'Malformed HTTPS reporting destination.',
                ]],
            );
        }

        $host = strtolower(rtrim($parts['host'], '.'));
        $path = $parts['path'] ?? '';
        $query = isset($parts['query']) ? '?' . $parts['query'] : '';
        $normalized = 'https://' . $host . $path . $query;

        return new TlsRptParsedDestination(
            rawUri: $rawUri,
            normalizedUri: $normalized,
            scheme: 'https',
            addressOrHost: $host,
            status: TlsRptParsedDestination::STATUS_VALID,
        );
    }
}
