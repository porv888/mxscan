<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist\Evaluation;

use App\Domain\EmailSecurity\Checks\Blacklist\Contracts\BlacklistDnsResolverInterface;

final class BlacklistDnsResolver implements BlacklistDnsResolverInterface
{
    public function __construct(
        private int $defaultTimeoutMs = 3000,
    ) {
    }

    public function queryA(string $queryHost, int $timeoutMs): BlacklistDnsQueryResult
    {
        $timeoutMs = $timeoutMs > 0 ? $timeoutMs : $this->defaultTimeoutMs;
        $started = hrtime(true);

        $url = 'https://dns.google/resolve?name=' . urlencode($queryHost) . '&type=A';
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT_MS => $timeoutMs,
            CURLOPT_CONNECTTIMEOUT_MS => min(1500, $timeoutMs),
            CURLOPT_HTTPHEADER => ['Accept: application/dns-json'],
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);

        $response = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        $errno = curl_errno($ch);
        curl_close($ch);

        $durationMs = (int) ((hrtime(true) - $started) / 1_000_000);

        if ($errno === CURLE_OPERATION_TIMEDOUT) {
            return new BlacklistDnsQueryResult(
                queryHost: $queryHost,
                success: false,
                dnsOutcome: 'TIMEOUT',
                durationMs: $durationMs,
                error: $curlError !== '' ? $curlError : 'Query timed out.',
                httpCode: $httpCode,
            );
        }

        if ($response === false || $httpCode !== 200) {
            return new BlacklistDnsQueryResult(
                queryHost: $queryHost,
                success: false,
                dnsOutcome: 'PROVIDER_ERROR',
                durationMs: $durationMs,
                error: $curlError !== '' ? $curlError : 'HTTP ' . $httpCode,
                httpCode: $httpCode,
            );
        }

        $data = json_decode($response, true);
        if (!is_array($data)) {
            return new BlacklistDnsQueryResult(
                queryHost: $queryHost,
                success: false,
                dnsOutcome: 'MALFORMED',
                durationMs: $durationMs,
                error: 'Malformed DNS JSON response.',
                httpCode: $httpCode,
            );
        }

        $status = (int) ($data['Status'] ?? 0);
        $addresses = [];
        foreach ($data['Answer'] ?? [] as $answer) {
            if (($answer['type'] ?? null) === 1 && isset($answer['data'])) {
                $addresses[] = (string) $answer['data'];
            }
        }

        $ttl = isset($data['Answer'][0]['TTL']) ? (int) $data['Answer'][0]['TTL'] : null;
        $dnsOutcome = match (true) {
            $status === 3 => 'NXDOMAIN',
            $addresses !== [] => 'ANSWER',
            default => 'NO_DATA',
        };

        return new BlacklistDnsQueryResult(
            queryHost: $queryHost,
            success: true,
            dnsOutcome: $dnsOutcome,
            addresses: $addresses,
            ttl: $ttl,
            durationMs: $durationMs,
            httpCode: $httpCode,
        );
    }
}
