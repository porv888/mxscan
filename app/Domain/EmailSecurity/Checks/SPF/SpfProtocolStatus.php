<?php

namespace App\Domain\EmailSecurity\Checks\SPF;

final class SpfProtocolStatus
{
    public const VALID = 'valid';
    public const NONE = 'none';
    public const PERMERROR = 'permerror';
    public const TEMPERROR = 'temperror';
    public const PARTIALLY_EVALUATED = 'partially_evaluated';
}
