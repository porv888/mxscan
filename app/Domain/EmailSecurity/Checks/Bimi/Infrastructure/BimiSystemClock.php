<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Infrastructure;

use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiClockInterface;

final class BimiSystemClock implements BimiClockInterface
{
    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }
}
