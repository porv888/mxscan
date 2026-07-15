<?php

namespace App\Domain\EmailSecurity\Checks\DKIM;

final class DkimSelectorSource
{
    public const EXPLICIT = 'explicit';
    public const SIGNATURE = 'signature';
    public const CONFIRMED = 'confirmed';
    public const PROVIDER = 'provider';
    public const CATALOG = 'catalog';

    /** @return list<string> */
    public static function priorityOrder(): array
    {
        return [
            self::EXPLICIT,
            self::SIGNATURE,
            self::CONFIRMED,
            self::PROVIDER,
            self::CATALOG,
        ];
    }

    public static function confidence(string $source): string
    {
        return match ($source) {
            self::EXPLICIT, self::SIGNATURE, self::CONFIRMED => 'high',
            self::PROVIDER => 'medium',
            default => 'low',
        };
    }

    public static function isAuthoritative(string $source): bool
    {
        return in_array($source, [self::EXPLICIT, self::SIGNATURE, self::CONFIRMED], true);
    }
}
