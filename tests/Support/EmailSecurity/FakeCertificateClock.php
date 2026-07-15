<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateClockInterface;

final class FakeCertificateClock implements CertificateClockInterface
{
    public const FIXED_NOW = 1784073631; // 2026-07-14T04:00:31+00:00

    public function now(): int
    {
        return self::FIXED_NOW;
    }
}
