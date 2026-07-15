<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Infrastructure;

use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateClockInterface;

final class SystemCertificateClock implements CertificateClockInterface
{
    public function now(): int
    {
        return time();
    }
}
