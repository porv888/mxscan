<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Reporting;

final class TlsRptMxscanRuaExpectations
{
    public const MXSCAN_DOMAIN = 'mxscan.me';

    /**
     * @param list<array<string, mixed>> $destinations
     * @return array{expected_address: ?string, present: bool, other_valid_destination_exists: bool}
     */
    public function evaluate(?string $expectedAddress, array $destinations): array
    {
        $expectedAddress = $this->normalizeExpected($expectedAddress);
        $present = false;
        $otherValid = false;

        foreach ($destinations as $destination) {
            if (($destination['status'] ?? '') !== 'valid') {
                continue;
            }

            $normalized = strtolower((string) ($destination['normalized_uri'] ?? ''));
            if ($expectedAddress !== null && $normalized === $expectedAddress) {
                $present = true;
                continue;
            }

            if ($normalized !== '') {
                $otherValid = true;
            }
        }

        return [
            'expected_address' => $expectedAddress,
            'present' => $present,
            'other_valid_destination_exists' => $otherValid,
        ];
    }

    public function resolveExpected(?string $override = null): ?string
    {
        $configured = $override ?? config('email-security.tls_rpt_expected_mailto');
        if (!is_string($configured) || trim($configured) === '') {
            return null;
        }

        return $this->normalizeExpected($configured);
    }

    public function isMxscanDestination(string $normalizedUri): bool
    {
        $normalizedUri = strtolower(trim($normalizedUri));
        if (!str_starts_with($normalizedUri, 'mailto:')) {
            return false;
        }

        $email = substr($normalizedUri, strlen('mailto:'));
        $at = strrpos($email, '@');

        return $at !== false && substr($email, $at + 1) === self::MXSCAN_DOMAIN;
    }

    private function normalizeExpected(?string $address): ?string
    {
        if ($address === null || trim($address) === '') {
            return null;
        }

        $address = strtolower(trim($address));
        if (str_starts_with($address, 'mailto:')) {
            return $address;
        }

        return 'mailto:' . $address;
    }
}
