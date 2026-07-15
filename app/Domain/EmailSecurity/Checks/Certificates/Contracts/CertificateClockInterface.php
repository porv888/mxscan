<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Contracts;

interface CertificateClockInterface
{
    public function now(): int;
}
