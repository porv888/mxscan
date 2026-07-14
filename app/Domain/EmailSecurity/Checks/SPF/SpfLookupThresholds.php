<?php

namespace App\Domain\EmailSecurity\Checks\SPF;

final class SpfLookupThresholds
{
    public const PRODUCT_WARNING_MIN = 7;
    public const RFC_LIMIT = 10;
    public const RFC_EXCEEDED = 11;
}
