<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Parsing;

final class TlsRptParsedRecord
{
    /**
     * @param array<string, array{raw: string, normalized: string}> $tags
     * @param list<string> $unknownTags
     * @param list<string> $duplicateTags
     * @param list<array{code: string, message: string}> $parseErrors
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
    ) {
    }

    public function tag(string $key): ?string
    {
        return $this->tags[$key]['raw'] ?? null;
    }
}
