<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\DTO;

final class BimiSelectorContext
{
    public const SOURCE_DEFAULT = 'default';
    public const SOURCE_EXPLICIT = 'explicit';
    public const SOURCE_HEADER = 'header';
    public const SOURCE_LOCAL_PART = 'local_part';
    public const SOURCE_PROVIDER = 'provider_confirmed';

    public function __construct(
        public readonly string $value,
        public readonly string $source,
        public readonly ?string $testLocalPart = null,
    ) {
    }
}
