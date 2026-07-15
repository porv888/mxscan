<?php

namespace App\Domain\EmailSecurity\Checks\DKIM;

final class DkimSelectorCandidate
{
    public function __construct(
        public readonly string $selector,
        public readonly string $source,
        public readonly string $confidence,
        public readonly string $hostname,
    ) {
    }
}
