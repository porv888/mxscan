<?php

namespace App\Domain\EmailSecurity\Checks\Mx\DTO;

final class MxEvidenceDTO
{
    /**
     * @param list<array{hostname: string, priority: int, normalized_hostname: string, status: string, usable: bool}> $hosts
     */
    public function __construct(
        public readonly array $hosts,
        public readonly string $serviceMode,
        public readonly bool $nullMxValid,
        public readonly bool $implicitFallbackActive,
    ) {
    }
}
