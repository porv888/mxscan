<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

final class BimiNativeResult
{
    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array<string, mixed>> $resolverDiagnostics
     * @param array<string, mixed> $record
     * @param array<string, mixed> $selector
     * @param array<string, mixed> $discovery
     * @param array<string, mixed> $indicator
     * @param array<string, mixed> $authorityEvidence
     * @param array<string, mixed> $indicatorComparison
     * @param array<string, mixed> $dmarcEligibility
     * @param list<array<string, mixed>> $providerProfiles
     * @param array<string, mixed> $localPartEvaluation
     * @param array<string, mixed> $standardsProfile
     */
    public function __construct(
        public readonly string $state,
        public readonly string $protocolStatus,
        public readonly string $readinessStatus,
        public readonly string $evidenceStatus,
        public readonly string $riskStatus,
        public readonly string $summary,
        public readonly string $domain,
        public readonly string $recordHostname,
        public readonly string $evaluationCompleteness,
        public readonly ?string $rawRecord = null,
        public readonly array $record = [],
        public readonly array $selector = [],
        public readonly array $discovery = [],
        public readonly array $indicator = [],
        public readonly array $authorityEvidence = [],
        public readonly array $indicatorComparison = [],
        public readonly array $dmarcEligibility = [],
        public readonly array $providerProfiles = [],
        public readonly array $localPartEvaluation = [],
        public readonly array $standardsProfile = [],
        public readonly array $errors = [],
        public readonly array $warnings = [],
        public readonly array $resolverDiagnostics = [],
        public readonly bool $hasMaterialWarnings = false,
    ) {
    }

    /**
     * @return list<string>
     */
    public function messageSummaries(): array
    {
        $messages = [$this->summary];
        foreach ($this->warnings as $warning) {
            $messages[] = $warning['message'] ?? '';
        }

        return array_values(array_filter($messages));
    }
}
