<?php

namespace App\Support;

class DomainNormalizer
{
    /**
     * Normalize user input to a bare hostname, or null if no usable candidate.
     */
    public static function normalize(string $input): ?string
    {
        $raw = trim($input);
        if ($raw === '') {
            return null;
        }

        $host = self::extractHost($raw);
        if ($host === null || $host === '') {
            return null;
        }

        $host = strtolower($host);
        $host = rtrim($host, '.');

        if (str_starts_with($host, 'www.')) {
            $host = substr($host, 4);
        }

        if ($host === '' || preg_match('/\s/', $host)) {
            return null;
        }

        if (self::isIpAddress($host)) {
            return null;
        }

        if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i', $host)) {
            return null;
        }

        return $host;
    }

    public static function isIpAddress(string $host): bool
    {
        $host = trim($host, '[]');

        return filter_var($host, FILTER_VALIDATE_IP) !== false;
    }

    protected static function extractHost(string $raw): ?string
    {
        $candidate = trim($raw);
        if ($candidate === '' || preg_match('#^[a-z][a-z0-9+.-]*://$#i', $candidate)) {
            return null;
        }

        if (!preg_match('#^[a-z][a-z0-9+.-]*://#i', $candidate)) {
            $candidate = 'http://' . $candidate;
        }

        $parts = @parse_url($candidate);
        if (is_array($parts) && !empty($parts['host'])) {
            return $parts['host'];
        }

        // Fallback when parse_url cannot extract a host.
        $fallback = preg_replace('#^[a-z][a-z0-9+.-]*://#i', '', $raw);
        if (!is_string($fallback) || $fallback === '') {
            return null;
        }
        $fallback = preg_replace('#^[^@]+@#', '', $fallback);
        $fallback = is_string($fallback) ? preg_replace('#[/?#].*$#', '', $fallback) : '';
        $fallback = is_string($fallback) ? preg_replace('#:\d+$#', '', $fallback) : '';

        $fallback = trim((string) $fallback);
        if ($fallback === '' || !str_contains($fallback, '.')) {
            return null;
        }

        return $fallback;
    }
}
