<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

final class BimiProtocolStatus
{
    public const VALID = 'valid';
    public const NONE = 'none';
    public const PERMERROR = 'permerror';
    public const TEMPERROR = 'temperror';
    public const PARTIALLY_EVALUATED = 'partially_evaluated';
    public const DECLINED = 'declined';
}
