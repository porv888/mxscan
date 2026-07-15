<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Parsing;

final class MtaStsParsedIndicator
{
    /**
     * @param array<string, string> $fields
     * @param array<string, string> $unknownFields
     * @param list<array{field: string, value: string}> $duplicateFields
     */
    public function __construct(
        public readonly ?string $version,
        public readonly ?string $id,
        public readonly string $rawRecord,
        public readonly string $normalizedRecord,
        public readonly array $fields,
        public readonly array $unknownFields,
        public readonly array $duplicateFields,
        public readonly bool $versionFirst,
        public readonly bool $malformed,
    ) {
    }
}
