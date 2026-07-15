<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Parsing;

final class DmarcParsedRecord
{
    /**
     * @param array<string, array{raw: string, normalized: string}> $tags
     * @param list<string> $duplicateTags
     * @param list<string> $unknownTags
     * @param list<array{code: string, message: string}> $parseErrors
     */
    public function __construct(
        public readonly string $rawRecord,
        public readonly string $normalizedRecord,
        public readonly array $tags,
        public readonly array $duplicateTags = [],
        public readonly array $unknownTags = [],
        public readonly array $parseErrors = [],
    ) {
    }

    public function tag(string $key, ?string $default = null): ?string
    {
        return $this->tags[$key]['normalized'] ?? $default;
    }
}
