<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist;

final class BlacklistTarget
{
    /**
     * @param list<string> $sourceHostnames
     */
    public function __construct(
        public readonly string $address,
        public readonly int $version,
        public readonly string $sourceType,
        public readonly array $sourceHostnames,
    ) {
    }

    public function cacheKey(): string
    {
        return $this->version . ':' . strtolower($this->address);
    }
}
