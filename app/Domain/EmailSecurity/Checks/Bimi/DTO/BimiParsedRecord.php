<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\DTO;

final class BimiParsedRecord
{
    /**
     * @param array<string, array{raw: string, normalized: string, present: bool}> $tags
     * @param list<string> $unknownTags
     * @param list<string> $duplicateTags
     * @param list<array{code: string, message: string}> $parseErrors
     * @param list<string> $lpsPrefixes
     */
    public function __construct(
        public readonly string $rawRecord,
        public readonly string $normalizedRecord,
        public readonly array $tags,
        public readonly array $unknownTags = [],
        public readonly array $duplicateTags = [],
        public readonly array $parseErrors = [],
        public readonly bool $versionFirst = false,
        public readonly bool $malformed = false,
        public readonly bool $declined = false,
        public readonly array $lpsPrefixes = [],
        public readonly string $avatarPreference = 'brand',
    ) {
    }

    public function tag(string $key): ?string
    {
        return $this->tags[$key]['normalized'] ?? $this->tags[$key]['raw'] ?? null;
    }

    public function tagPresent(string $key): bool
    {
        return isset($this->tags[$key]) && ($this->tags[$key]['present'] ?? false);
    }

    public function tagRaw(string $key): ?string
    {
        return $this->tags[$key]['raw'] ?? null;
    }
}
