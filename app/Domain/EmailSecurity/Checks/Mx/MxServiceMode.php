<?php

namespace App\Domain\EmailSecurity\Checks\Mx;

final class MxServiceMode
{
    public const ACCEPTS_MAIL = 'accepts_mail';
    public const NO_INBOUND_MAIL = 'no_inbound_mail';
    public const IMPLICIT_DELIVERY = 'implicit_delivery';
    public const UNKNOWN = 'unknown';
}
