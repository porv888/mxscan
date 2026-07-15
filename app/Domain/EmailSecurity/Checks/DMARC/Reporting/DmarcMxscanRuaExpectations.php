<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Reporting;

final class DmarcMxscanRuaExpectations
{
    public const MXSCAN_DOMAIN = 'mxscan.me';

    /**
     * @param list<array<string, mixed>> $destinations
     * @return array{expected_address: ?string, present: bool, other_valid_destination_exists: bool}
     */
    public function evaluate(?string $expectedAddress, array $destinations): array
    {
        $expectedAddress = $expectedAddress !== null ? strtolower(trim($expectedAddress)) : null;
        $present = false;
        $otherValid = false;

        foreach ($destinations as $destination) {
            $email = strtolower((string) ($destination['normalized_destination'] ?? ''));
            if ($expectedAddress !== null && $email === $expectedAddress) {
                $present = true;
                continue;
            }

            if ($email !== '') {
                $otherValid = true;
            }
        }

        return [
            'expected_address' => $expectedAddress,
            'present' => $present,
            'other_valid_destination_exists' => $otherValid,
        ];
    }

    public function isMxscanEmail(string $email): bool
    {
        $email = strtolower(trim($email));
        $at = strrpos($email, '@');

        return $at !== false && substr($email, $at + 1) === self::MXSCAN_DOMAIN;
    }
}
