<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist;

final class BlacklistNativeResult
{
    /**
     * @param list<array<string, mixed>> $targets
     * @param list<array<string, mixed>> $providers
     * @param list<array<string, mixed>> $checks
     * @param list<array<string, mixed>> $targetResults
     * @param list<array<string, mixed>> $providerHealth
     * @param list<array<string, mixed>> $listings
     * @param array<string, int> $counts
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     */
    public function __construct(
        public readonly string $domain,
        public readonly string $analysisStatus,
        public readonly string $reputationStatus,
        public readonly string $state,
        public readonly string $summary,
        public readonly string $evaluationCompleteness,
        public readonly ?string $mxEvidenceVersion,
        public readonly array $targets,
        public readonly array $providers,
        public readonly array $checks,
        public readonly array $targetResults,
        public readonly array $providerHealth,
        public readonly array $listings,
        public readonly array $counts,
        public readonly array $errors = [],
        public readonly array $warnings = [],
    ) {
    }
}
