<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Parsing;

final class DkimParsedRecord
{
    /**
     * @param array<string, string> $tags
     * @param array<string, list<string>> $duplicateTags
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

    public function tag(string $key): ?string
    {
        return $this->tags[$key] ?? null;
    }

    public function hasParseErrors(): bool
    {
        return $this->parseErrors !== [];
    }
}
