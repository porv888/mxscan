<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateClockInterface;

final class CertificateValidityEvaluator
{
    public const STATUS_NOT_YET_VALID = 'not_yet_valid';
    public const STATUS_VALID = 'valid';
    public const STATUS_EXPIRING_SOON = 'expiring_soon';
    public const STATUS_EXPIRING_CRITICAL = 'expiring_critical';
    public const STATUS_EXPIRING_URGENT = 'expiring_urgent';
    public const STATUS_EXPIRED = 'expired';
    public const STATUS_UNKNOWN = 'unknown';

    public function __construct(
        private CertificateClockInterface $clock,
    ) {
    }

    public function evaluate(?int $validFromTimestamp, ?int $validToTimestamp): string
    {
        if ($validFromTimestamp === null && $validToTimestamp === null) {
            return self::STATUS_UNKNOWN;
        }

        $now = $this->clock->now();

        if ($validFromTimestamp !== null && $validFromTimestamp > $now) {
            return self::STATUS_NOT_YET_VALID;
        }

        if ($validToTimestamp !== null && $validToTimestamp < $now) {
            return self::STATUS_EXPIRED;
        }

        if ($validToTimestamp === null) {
            return self::STATUS_UNKNOWN;
        }

        $daysRemaining = (int) floor(($validToTimestamp - $now) / 86400);
        $urgentDays = (int) config('email-security.certificates.expiry_urgent_days', 7);
        $criticalDays = (int) config('email-security.certificates.expiry_critical_days', 14);
        $warningDays = (int) config('email-security.certificates.expiry_warning_days', 30);

        if ($daysRemaining <= $urgentDays) {
            return self::STATUS_EXPIRING_URGENT;
        }

        if ($daysRemaining <= $criticalDays) {
            return self::STATUS_EXPIRING_CRITICAL;
        }

        if ($daysRemaining <= $warningDays) {
            return self::STATUS_EXPIRING_SOON;
        }

        return self::STATUS_VALID;
    }

    public function isExpiryWarning(string $classification): bool
    {
        return in_array($classification, [
            self::STATUS_EXPIRING_SOON,
            self::STATUS_EXPIRING_CRITICAL,
            self::STATUS_EXPIRING_URGENT,
        ], true);
    }
}
