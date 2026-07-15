<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist;

final class BlacklistProviderDefinition
{
    /**
     * @param list<string> $targetTypes ipv4|ipv6
     * @param list<string> $listingCodes
     * @param list<string> $blockedCodes
     * @param list<string> $rateLimitCodes
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public readonly string $key,
        public readonly string $name,
        public readonly string $zone,
        public readonly ?string $ipv6Zone,
        public readonly bool $enabled,
        public readonly array $targetTypes,
        public readonly string $interpreter,
        public readonly array $listingCodes,
        public readonly array $blockedCodes,
        public readonly array $rateLimitCodes,
        public readonly bool $nxdomainMeansClean,
        public readonly bool $noDataMeansClean,
        public readonly int $timeoutMs,
        public readonly int $maxRetries,
        public readonly string $delistUrl,
        public readonly array $metadata = [],
    ) {
    }

    public function supportsIpv4(): bool
    {
        return in_array('ipv4', $this->targetTypes, true);
    }

    public function supportsIpv6(): bool
    {
        return in_array('ipv6', $this->targetTypes, true);
    }

    public function zoneForVersion(int $version): ?string
    {
        return match ($version) {
            4 => $this->supportsIpv4() ? $this->zone : null,
            6 => $this->supportsIpv6() ? ($this->ipv6Zone ?? $this->zone) : null,
            default => null,
        };
    }
}
