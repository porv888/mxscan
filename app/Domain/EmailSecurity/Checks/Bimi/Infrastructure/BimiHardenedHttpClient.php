<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Infrastructure;

use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiHttpClientInterface;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiUriValidator;
use Illuminate\Support\Facades\Http;

final class BimiHardenedHttpClient implements BimiHttpClientInterface
{
    public function __construct(
        private BimiUriValidator $uriValidator,
    ) {
    }

    public function fetch(string $url): array
    {
        $validation = $this->uriValidator->validate($url);
        if (!$validation['valid']) {
            return $this->failure(
                $url,
                $validation['errors'][0]['message'] ?? 'URI validation failed.',
                'uri_validation',
                [],
                0,
            );
        }

        $host = (string) $validation['host'];
        $safety = $this->uriValidator->resolveHostSafety($host);
        if (!$safety['safe']) {
            return $this->failure($url, $safety['message'], 'ssrf_blocked', $safety['resolved_ips'], 0);
        }

        $pinIp = $this->selectPinIp($safety['resolved_ips']);
        $connectTimeout = (int) config('bimi.fetch.connect_timeout_seconds', 5);
        $responseTimeout = (int) config('bimi.fetch.response_timeout_seconds', 10);
        $maxBytes = (int) config('bimi.fetch.max_download_bytes', 65536);
        $allowedPort = (int) config('bimi.fetch.allowed_port', 443);

        $start = microtime(true);
        $curlOptions = [
            CURLOPT_RESOLVE => $pinIp !== null ? ["{$host}:{$allowedPort}:{$pinIp}"] : [],
        ];

        try {
            $response = Http::withOptions([
                'verify' => true,
                'allow_redirects' => false,
                'connect_timeout' => $connectTimeout,
                'timeout' => $responseTimeout,
                'curl' => $curlOptions,
            ])->withHeaders([
                'Accept' => '*/*',
            ])->get($validation['normalized_uri'] ?? $url);

            $durationMs = (int) round((microtime(true) - $start) * 1000);
            $statusCode = $response->status();

            if ($statusCode >= 300 && $statusCode < 400) {
                return $this->failure(
                    $url,
                    'Redirects are not permitted for BIMI fetches.',
                    'redirect',
                    $safety['resolved_ips'],
                    $durationMs,
                    $statusCode,
                );
            }

            if ($statusCode !== 200) {
                return $this->failure(
                    $url,
                    'HTTP response status was ' . $statusCode . '.',
                    'http_non_200',
                    $safety['resolved_ips'],
                    $durationMs,
                    $statusCode,
                );
            }

            $body = (string) $response->body();
            if (strlen($body) > $maxBytes) {
                return $this->failure(
                    $url,
                    'Response body exceeds maximum allowed size.',
                    'body_too_large',
                    $safety['resolved_ips'],
                    $durationMs,
                    $statusCode,
                );
            }

            $contentType = $response->header('Content-Type');

            return [
                'success' => true,
                'url' => $validation['normalized_uri'] ?? $url,
                'http_status' => $statusCode,
                'content_type' => is_string($contentType) ? $contentType : null,
                'body' => $body,
                'duration_ms' => $durationMs,
                'tls_verified' => true,
                'error' => null,
                'failure_category' => null,
                'resolved_ips' => $safety['resolved_ips'],
            ];
        } catch (\Illuminate\Http\Client\ConnectionException $e) {
            return $this->failure(
                $url,
                'Connection timed out.',
                'connection_timeout',
                $safety['resolved_ips'],
                (int) round((microtime(true) - $start) * 1000),
            );
        } catch (\Throwable $e) {
            $message = strtolower($e->getMessage());
            $category = str_contains($message, 'certificate') || str_contains($message, 'ssl')
                ? 'certificate_failure'
                : (str_contains($message, 'tls') ? 'tls_handshake_failure' : 'connection_timeout');

            return $this->failure(
                $url,
                $e->getMessage(),
                $category,
                $safety['resolved_ips'],
                (int) round((microtime(true) - $start) * 1000),
            );
        }
    }

    /**
     * @param list<string> $resolvedIps
     */
    private function selectPinIp(array $resolvedIps): ?string
    {
        foreach ($resolvedIps as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                return $ip;
            }
        }

        foreach ($resolvedIps as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                return $ip;
            }
        }

        return null;
    }

    /**
     * @param list<string> $resolvedIps
     * @return array<string, mixed>
     */
    private function failure(
        string $url,
        string $error,
        string $category,
        array $resolvedIps,
        int $durationMs,
        ?int $httpStatus = null,
    ): array {
        return [
            'success' => false,
            'url' => $url,
            'http_status' => $httpStatus,
            'content_type' => null,
            'body' => null,
            'duration_ms' => $durationMs,
            'tls_verified' => false,
            'error' => $error,
            'failure_category' => $category,
            'resolved_ips' => $resolvedIps,
        ];
    }
}
