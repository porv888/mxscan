<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Contracts;

interface BimiClockInterface
{
    public function now(): \DateTimeImmutable;
}
