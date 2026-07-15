<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiHttpClientInterface;

final class BimiIndicatorFetcher
{
    public function __construct(
        private BimiHttpClientInterface $httpClient,
        private BimiSvgzDecompressor $svgzDecompressor,
        private BimiSvgValidator $svgValidator,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function fetch(string $uri): array
    {
        $response = $this->httpClient->fetch($uri);

        $fetch = [
            'source_uri' => $uri,
            'normalized_uri' => $response['url'] ?? $uri,
            'http_status' => $response['http_status'] ?? null,
            'tls_verified' => $response['tls_verified'] ?? false,
            'content_type' => $response['content_type'] ?? null,
            'content_length' => null,
            'downloaded_bytes' => $response['body'] !== null ? strlen((string) $response['body']) : 0,
            'decompressed_bytes' => 0,
            'duration_ms' => $response['duration_ms'] ?? 0,
            'redirects' => [],
            'errors' => [],
            'warnings' => [],
            'resolved_ips' => $response['resolved_ips'] ?? [],
        ];

        if (!($response['success'] ?? false)) {
            $fetch['errors'][] = [
                'code' => strtoupper((string) ($response['failure_category'] ?? 'fetch_failed')),
                'message' => (string) ($response['error'] ?? 'Indicator fetch failed.'),
            ];

            return [
                'status' => 'unavailable',
                'format' => $this->detectFormat($uri, null),
                'fetch' => $fetch,
                'validation' => null,
                'decompressed_bytes' => null,
                'sha256' => null,
            ];
        }

        $body = (string) $response['body'];
        $format = $this->detectFormat($uri, $response['content_type'] ?? null);
        $decompressed = $body;
        $decompressedBytes = strlen($body);

        if ($format === 'svgz' || $this->isGzipEncoded($response['content_type'] ?? null)) {
            $gzip = $this->svgzDecompressor->decompress($body);
            if (!$gzip['success']) {
                $fetch['errors'] = array_merge($fetch['errors'], $gzip['errors']);

                return [
                    'status' => 'invalid',
                    'format' => 'svgz',
                    'fetch' => $fetch,
                    'validation' => null,
                    'decompressed_bytes' => null,
                    'sha256' => null,
                ];
            }

            $decompressed = (string) $gzip['bytes'];
            $decompressedBytes = $gzip['decompressed_bytes'];
            $format = 'svg';
        }

        $fetch['decompressed_bytes'] = $decompressedBytes;
        $validation = $this->svgValidator->validate($decompressed);
        $sha256 = hash('sha256', $decompressed);

        return [
            'status' => $validation['valid'] ? 'valid' : 'invalid',
            'format' => $format,
            'fetch' => $fetch,
            'validation' => $validation,
            'decompressed_bytes' => $decompressedBytes,
            'sha256' => $sha256,
            '_decompressed_svg' => $validation['valid'] ? $decompressed : null,
        ];
    }

    private function detectFormat(string $uri, ?string $contentType): string
    {
        $lower = strtolower($uri);
        if (str_ends_with($lower, '.svgz')) {
            return 'svgz';
        }

        if (str_ends_with($lower, '.svg')) {
            return 'svg';
        }

        if (is_string($contentType) && str_contains(strtolower($contentType), 'svg')) {
            return 'svg';
        }

        return 'unknown';
    }

    private function isGzipEncoded(?string $contentType): bool
    {
        return is_string($contentType) && str_contains(strtolower($contentType), 'gzip');
    }
}
