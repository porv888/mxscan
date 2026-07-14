<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Parsing;

final class SpfParsedTerm
{
    /**
     * @param list<array{code: string, message: string}> $errors
     */
    public function __construct(
        public readonly int $position,
        public readonly string $raw,
        public readonly string $qualifier,
        public readonly string $type,
        public readonly string $name,
        public readonly ?string $argument = null,
        public readonly ?int $cidrV4 = null,
        public readonly ?int $cidrV6 = null,
        public readonly string $sourceDomain = '',
        public readonly array $errors = [],
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'position' => $this->position,
            'raw' => $this->raw,
            'qualifier' => $this->qualifier,
            'type' => $this->type,
            'name' => $this->name,
            'argument' => $this->argument,
            'cidr_v4' => $this->cidrV4,
            'cidr_v6' => $this->cidrV6,
            'source_domain' => $this->sourceDomain,
            'errors' => $this->errors,
        ];
    }
}
