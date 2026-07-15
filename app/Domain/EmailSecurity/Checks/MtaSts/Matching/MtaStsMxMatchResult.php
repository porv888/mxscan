<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Matching;

final class MtaStsMxMatchResult
{
    public function __construct(
        public readonly string $hostname,
        public readonly int $priority,
        public readonly bool $matchesPolicy,
        public readonly ?string $matchedPattern = null,
        public readonly ?string $mismatchReason = null,
    ) {
    }
}
