<?php

namespace Tests\Support\EmailSecurity;

final class BimiTestFixtures
{
    public const VALID_SVG = '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100"><title>Logo</title><rect width="100" height="100" fill="#3366cc"/></svg>';

    public static function validSvgSha256(): string
    {
        return hash('sha256', self::VALID_SVG);
    }
}
