<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiHttpClientInterface;

final class BimiEvidenceDocumentFetcher
{
    public function __construct(
        private BimiHttpClientInterface $httpClient,
        private BimiMarkCertificateParser $certificateParser,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function fetch(string $uri): array
    {
        $maxPemBytes = (int) config('bimi.mark_certificate.max_pem_bytes', 1048576);
        $response = $this->httpClient->fetch($uri);

        $fetch = [
            'source_uri' => $uri,
            'normalized_uri' => $response['url'] ?? $uri,
            'http_status' => $response['http_status'] ?? null,
            'tls_verified' => $response['tls_verified'] ?? false,
            'content_type' => $response['content_type'] ?? null,
            'downloaded_bytes' => $response['body'] !== null ? strlen((string) $response['body']) : 0,
            'duration_ms' => $response['duration_ms'] ?? 0,
            'errors' => [],
            'warnings' => [],
            'resolved_ips' => $response['resolved_ips'] ?? [],
        ];

        if (!($response['success'] ?? false)) {
            $fetch['errors'][] = [
                'code' => strtoupper((string) ($response['failure_category'] ?? 'fetch_failed')),
                'message' => (string) ($response['error'] ?? 'Evidence document fetch failed.'),
            ];

            return [
                'status' => 'unavailable',
                'fetch' => $fetch,
                'pem' => null,
                'certificates' => [],
            ];
        }

        $body = (string) $response['body'];
        if (strlen($body) > $maxPemBytes) {
            $fetch['errors'][] = [
                'code' => 'PEM_TOO_LARGE',
                'message' => 'Evidence PEM exceeds maximum allowed size.',
            ];

            return [
                'status' => 'malformed',
                'fetch' => $fetch,
                'pem' => null,
                'certificates' => [],
            ];
        }

        $parsed = $this->certificateParser->parsePemBundle($body);
        if (!$parsed['success']) {
            $fetch['errors'] = array_merge($fetch['errors'], $parsed['errors']);

            return [
                'status' => 'malformed',
                'fetch' => $fetch,
                'pem' => $body,
                'certificates' => [],
            ];
        }

        return [
            'status' => 'fetched',
            'fetch' => $fetch,
            'pem' => $body,
            'certificates' => $parsed['certificates'],
        ];
    }
}
