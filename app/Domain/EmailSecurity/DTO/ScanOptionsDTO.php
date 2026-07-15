<?php

namespace App\Domain\EmailSecurity\DTO;

final class ScanOptionsDTO
{
    public function __construct(
        public readonly bool $dns = true,
        public readonly bool $spf = true,
        public readonly bool $blacklist = true,
        public readonly bool $dkim = false,
        public readonly bool $monitoring = true,
        public readonly ?string $scanId = null,
        public readonly ?string $dkimSelector = null,
        public readonly ?string $dkimSignature = null,
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
            dkim: (bool) ($options['dkim'] ?? false),
            monitoring: (bool) ($options['monitoring'] ?? true),
            scanId: isset($options['scan_id']) ? (string) $options['scan_id'] : null,
            dkimSelector: isset($options['dkim_selector']) ? (string) $options['dkim_selector'] : null,
            dkimSignature: isset($options['dkim_signature']) ? (string) $options['dkim_signature'] : null,
        );
    }
}
