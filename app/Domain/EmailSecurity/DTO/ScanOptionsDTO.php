<?php

namespace App\Domain\EmailSecurity\DTO;

final class ScanOptionsDTO
{
    public function __construct(
        public readonly bool $dns = true,
        public readonly bool $spf = true,
        public readonly bool $blacklist = true,
        public readonly bool $monitoring = true,
        public readonly ?string $scanId = null,
    ) {
    }

    /**
     * @param array<string, mixed> $options
     */
    public static function fromArray(array $options): self
    {
        return new self(
            dns: (bool) ($options['dns'] ?? true),
            spf: (bool) ($options['spf'] ?? true),
            blacklist: (bool) ($options['blacklist'] ?? true),
            monitoring: (bool) ($options['monitoring'] ?? true),
            scanId: isset($options['scan_id']) ? (string) $options['scan_id'] : null,
        );
    }
}
