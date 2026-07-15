<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Parsing;

final class MtaStsParsedPolicy
{
    /**
     * @param list<string> $mxPatterns
     * @param list<array{line: int, key: string, value: string}> $lines
     * @param list<array{field: string, value: string}> $duplicateFields
     * @param array<string, string> $unknownFields
     */
    public function __construct(
        public readonly ?string $version,
        public readonly ?string $mode,
        public readonly ?int $maxAge,
        public readonly array $mxPatterns,
        public readonly string $rawBody,
        public readonly array $lines,
        public readonly array $duplicateFields,
        public readonly array $unknownFields,
        public readonly bool $malformed,
    ) {
    }
}
